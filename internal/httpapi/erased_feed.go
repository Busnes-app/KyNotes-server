package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

const erasedCursor = "erased_poll_revision"

// PollErased reconciles the authenticated suite feed on the elected worker. Fetching stays
// outside the writer transaction; fences, access revocation, ownership transfer and the cursor
// commit together. Restores clear the cursor so notices since zero are applied again.
func PollErased(ctx context.Context, db *sql.DB, dir suitedir.Client) error {
	tenancy, err := storage.TenancyOfContext(ctx, db)
	if err != nil || !tenancy.Multi() {
		return err
	}
	since, err := readErasedCursor(ctx, db)
	if err != nil {
		return err
	}
	notices, _, err := dir.Erased(ctx, since)
	if err != nil {
		return err
	}
	// One member per transaction: a long replay never holds the global writer for the feed.
	for _, n := range notices {
		applied, err := applyErasedNotice(ctx, db, dir.Issuer, since, n)
		if err != nil || !applied {
			return err
		}
		since = n.Revision
	}
	return nil
}

func readErasedCursor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(CAST(value AS BIGINT)),0) FROM server_settings WHERE key=?`, erasedCursor).Scan(&n)
	return n, err
}

func applyErasedNotice(ctx context.Context, db *sql.DB, issuer string, since int64, notice suitedir.ErasedSubject) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	current, err := readErasedCursor(ctx, tx)
	if err != nil {
		return false, err
	}
	if current != since {
		return false, nil
	} // Another replica committed first; fetch its remainder next tick.
	if err := eraseSubjectTx(ctx, tx, issuer, notice.Sub, notice.OrgID, notice.Revision); err != nil {
		return false, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, erasedCursor, strconv.FormatInt(notice.Revision, 10), now); err != nil {
		return false, err
	}
	if err := storage.RecordAuditOutcomeTx(tx, "", "directory.erase_reconcile", "", "", "success", "notices=1", "erased-poll"); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// eraseSubjectTx is shared by the signed webhook and the authenticated replay feed. Unknown
// subjects still get a fence; an org mismatch refuses that notice without advancing past it.
func eraseSubjectTx(ctx context.Context, tx *sql.Tx, issuer, subject, org string, revision int64) error {
	var user, accountOrg string
	err := tx.QueryRowContext(ctx, `SELECT id,org_id FROM users WHERE sso_issuer=? AND sso_subject=?`, issuer, subject).Scan(&user, &accountOrg)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if user != "" && accountOrg != org {
		return errors.New("erased feed: account org differs")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO erased_subjects(subject,org_id,revision) VALUES(?,?,?) ON CONFLICT(subject) DO NOTHING`, subject, org, revision); err != nil {
		return err
	}
	var savedOrg string
	if err := tx.QueryRowContext(ctx, `SELECT org_id FROM erased_subjects WHERE subject=?`, subject).Scan(&savedOrg); err != nil {
		return err
	}
	if savedOrg != org {
		return errors.New("erased feed: subject org differs")
	}
	if user == "" {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, q := range []string{`UPDATE sessions SET revoked_at=? WHERE`, `UPDATE devices SET revoked_at=? WHERE platform<>'identity' AND`} {
		if _, err := tx.ExecContext(ctx, q+` user_id=? AND revoked_at=''`, now, user); err != nil {
			return err
		}
	}
	return eraseMemberTx(tx, user)
}
