// Package orgsync mirrors KyIdentity's org directory (/api/suite/orgs) into the orgs table, so
// every request reads its org's status from the database (tenancy spec N9).
package orgsync

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// cursorKey is the server_settings row holding the revision to ask for next.
const cursorKey = "org_poll_revision"

// ListFunc is suitedir.Client.Orgs.
type ListFunc func(ctx context.Context, since int64) ([]suitedir.Org, int64, error)

// Poller applies one poll at a time. A failed poll changes nothing.
type Poller struct {
	db    *sql.DB
	list  ListFunc
	turn  chan struct{} // single flight: holding its one slot is running a poll
	tried map[string]time.Time
	now   func() time.Time
}

func New(db *sql.DB, list ListFunc) *Poller {
	return &Poller{db: db, list: list, turn: make(chan struct{}, 1), tried: map[string]time.Time{}, now: time.Now}
}

// acquire waits for the poll slot, or gives up when ctx ends, so no caller waits past its own
// bound behind a slow poll.
func (p *Poller) acquire(ctx context.Context) error {
	select {
	case p.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Poller) release() { <-p.turn }

// Poll asks for the orgs changed since the stored cursor and applies them in one transaction.
func (p *Poller) Poll(ctx context.Context) error {
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()
	return p.poll(ctx)
}

func (p *Poller) poll(ctx context.Context) error {
	var since int64
	if err := p.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(CAST(value AS BIGINT)),0) FROM server_settings WHERE key=?`, cursorKey).Scan(&since); err != nil {
		return err
	}
	orgs, next, err := p.list(ctx, since)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := p.now().UTC().Format(time.RFC3339)
	serves := `SELECT count(*) FROM orgs o WHERE o.id=? AND o.status='active' AND o.enabled=1 AND ` + storage.InServedCell("o")
	for _, o := range orgs {
		enabled := 0
		if o.Enabled {
			enabled = 1
		}
		var before int
		if err = tx.QueryRowContext(ctx, serves, o.ID).Scan(&before); err != nil {
			return err
		}
		// A listing never moves an org back to an older revision; an equal one is the same state.
		if _, err = tx.ExecContext(ctx, `INSERT INTO orgs(id,status,revision,enabled,home_region,seen_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,revision=excluded.revision,enabled=excluded.enabled,home_region=excluded.home_region,seen_at=excluded.seen_at WHERE excluded.revision>=orgs.revision`, o.ID, o.Status, o.Revision, enabled, o.HomeRegion, seen); err != nil {
			return err
		}
		var after int
		if err = tx.QueryRowContext(ctx, serves, o.ID).Scan(&after); err != nil {
			return err
		}
		// An org that stops serving loses its sessions with the change, and the change is audited
		// as a platform row. Devices, identities and envelopes stay, so a resume needs no
		// re-linking (spec, Lifecycle, Suspended or deletion_scheduled).
		if before == 1 && after == 0 {
			// A deletion_scheduled org keeps its export_only sessions: a member who signed in to
			// export just before the poll is not cut off (spec N11).
			keep := "0"
			if o.Status == "deletion_scheduled" {
				keep = "1"
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id=?) AND NOT (export_only=1 AND ?='1')`, o.ID, keep)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			if err = storage.RecordAuditOutcomeTx(tx, "", "org.sessions_ended", "", o.ID, "success", "status="+o.Status+",sessions="+strconv.FormatInt(n, 10), "org-poll"); err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, cursorKey, strconv.FormatInt(next, 10), seen); err != nil {
		return err
	}
	return tx.Commit()
}

// unknownGate is how often one unmirrored org ID may trigger a poll (spec, Sign-in, step 2).
const unknownGate = 10 * time.Second

// Await makes an unmirrored org known if KyIdentity lists it: one poll, shared with any poll
// already running, at most once every unknownGate per org ID. It reports whether org is now
// mirrored. The caller bounds the wait with ctx (the sign-in waits 5 s).
func (p *Poller) Await(ctx context.Context, org string) (bool, error) {
	mirrored := func() (bool, error) {
		var n int
		err := p.db.QueryRowContext(ctx, `SELECT count(*) FROM orgs WHERE id=?`, org).Scan(&n)
		return n > 0, err
	}
	if ok, err := mirrored(); ok || err != nil {
		return ok, err
	}
	if err := p.acquire(ctx); err != nil {
		return false, nil // the caller's wait ended behind a running poll: still unmirrored
	}
	defer p.release()
	if ok, err := mirrored(); ok || err != nil { // a poll ahead of us may have listed it
		return ok, err
	}
	now := p.now()
	if last, ok := p.tried[org]; ok && now.Sub(last) < unknownGate {
		return false, nil
	}
	for id, at := range p.tried { // bounded: entries live unknownGate
		if now.Sub(at) >= unknownGate {
			delete(p.tried, id)
		}
	}
	p.tried[org] = now
	if err := p.poll(ctx); err != nil {
		return false, err
	}
	return mirrored()
}
