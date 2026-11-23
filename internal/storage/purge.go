package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// purgeBatch is the most rows one purge transaction deletes, so no batch holds the writer
// lock (N3) long enough to stall other orgs (spec, Lifecycle, Deleted; C measured 500).
var purgeBatch = 500

// A purge step deletes one table's rows of the org, keyed by key, children before parents, so
// no statement cascades a whole history. scope names the org with one or more ?.
type purgeStep struct{ table, key, scope string }

const (
	orgContainers = `(SELECT id FROM containers WHERE org_id=?)`
	orgObjects    = `(SELECT o.id FROM objects o JOIN containers c ON c.id=o.container_id WHERE c.org_id=?)`
	orgUsers      = `(SELECT id FROM users WHERE org_id=?)`
	orgDevices    = `(SELECT d.id FROM devices d JOIN users u ON u.id=d.user_id WHERE u.org_id=?)`
)

// purgeSteps is the purge order. TestPurgeOrderCoversEveryCascade fails when a table with a
// cascading foreign key to a purged table is missing from it.
var purgeSteps = []purgeStep{
	// Containers, bottom-up.
	{"activity", "id", "container_id IN " + orgContainers},
	{"share_links", "id", "object_id IN " + orgObjects},
	{"attachment_refs", "attachment_id,object_id,object_version", "object_id IN " + orgObjects},
	{"mentions", "comment_id,mentioned_user_id", "comment_id IN (SELECT id FROM comments WHERE container_id IN " + orgContainers + ")"},
	{"comments", "id", "container_id IN " + orgContainers},
	{"conflicts", "id", "org_id=?"},
	{"object_versions", "object_id,version", "org_id=?"},
	{"attachments", "id", "org_id=?"},
	{"upload_sessions", "id", "org_id=?"},
	{"objects", "id", "container_id IN " + orgContainers},
	{"invitation_envelopes", "invitation_id,container_id", "container_id IN " + orgContainers},
	{"invitations", "id", "container_id IN " + orgContainers},
	{"key_envelopes", "id", "container_id IN " + orgContainers},
	{"device_containers", "device_id,container_id", "container_id IN " + orgContainers},
	{"blob_containers", "digest,container_id", "org_id=?"},
	{"memberships", "id", "container_id IN " + orgContainers},
	{"containers", "id", "org_id=?"},
	{"blobs", "org_id,digest", "org_id=?"},
	// Users: first the rows with no foreign key, then each user's rows, the users last.
	{"audit_events", "id", "org_id=?"},
	{"sealed_share_links", "id", "org_id=?"},
	{"pairing_nonces", "nonce", "user_id IN " + orgUsers},
	{"sso_directory_state", "issuer,subject", "(issuer,subject) IN (SELECT sso_issuer,sso_subject FROM users WHERE org_id=? AND sso_subject<>'')"},
	{"sso_login_cutoffs", "issuer,subject", "(issuer,subject) IN (SELECT sso_issuer,sso_subject FROM users WHERE org_id=? AND sso_subject<>'')"},
	{"link_requests", "id", "user_id IN " + orgUsers},
	{"sso_stepup", "id", "session_id IN (SELECT id FROM sessions WHERE user_id IN " + orgUsers + ")"},
	{"sessions", "id", "user_id IN " + orgUsers},
	{"push_registrations", "device_id", "device_id IN " + orgDevices},
	{"user_identities", "user_id", "user_id IN " + orgUsers},
	{"devices", "id", "user_id IN " + orgUsers},
	{"reminders", "id", "user_id IN " + orgUsers},
	{"web_push_subscriptions", "id", "user_id IN " + orgUsers},
	{"users", "id", "org_id=?"},
}

// PurgeDeletedOrgs purges every deleted org not yet purged. It runs on the elected worker in
// multi mode only; single mode has no deleted org and does nothing here.
func PurgeDeletedOrgs(ctx context.Context, db *sql.DB) error {
	tenancy, err := TenancyOf(db)
	if err != nil || !tenancy.Multi() {
		return err
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM orgs WHERE status='deleted' AND purged_at=''`)
	if err != nil {
		return err
	}
	var orgs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, id)
	}
	rows.Close()
	for _, org := range orgs {
		if err := PurgeOrg(ctx, db, org); err != nil {
			return err
		}
	}
	return rows.Err()
}

// PurgeOrg deletes every row of one deleted org in short batches behind a fail-closed audit row,
// then marks its tombstone purged (spec, Lifecycle, Deleted). It is idempotent: a purge killed
// between batches finishes on its next run. The org's blob files are not deleted here: until the
// per-org blob layout (spec N8, PR 5a) two orgs' identical ciphertext share one file, so only
// rows are purged and the orphan sweep removes files nothing references.
func PurgeOrg(ctx context.Context, db *sql.DB, org string) error {
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM orgs WHERE id=?`, org).Scan(&status); err != nil {
		return err
	}
	if status != "deleted" || org == DefaultOrgID {
		return fmt.Errorf("purge: org is %s", status)
	}
	if err := RecordAuditOutcome(db, "", "platform.org_purge_started", "", org, "success", "", "org-purge"); err != nil {
		return err // nothing is deleted without the record that the purge began
	}
	progress := "purge_rows:" + org + ":"
	for _, step := range purgeSteps {
		if _, err := purgeTable(ctx, db, step, org, progress+step.table); err != nil {
			return fmt.Errorf("purge %s: %w", step.table, err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The counts of every run of this purge, kept with each batch, so a resumed purge's audit
	// still describes all of it.
	counts := make([]string, 0, len(purgeSteps))
	for _, step := range purgeSteps {
		var n string
		err := tx.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key=?`, progress+step.table).Scan(&n)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		counts = append(counts, step.table+"="+n)
		if _, err = tx.ExecContext(ctx, `DELETE FROM server_settings WHERE key=?`, progress+step.table); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE orgs SET purged_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), org); err != nil {
		return err
	}
	if err = RecordAuditOutcomeTx(tx, "", "platform.org_deleted", "", org, "success", strings.Join(counts, ","), "org-purge"); err != nil {
		return err
	}
	return tx.Commit()
}

// purgeTable deletes the step's rows in batches. When progress names a server_settings row, each
// batch adds its count there in its own transaction.
func purgeTable(ctx context.Context, db *sql.DB, step purgeStep, org, progress string) (int64, error) {
	key := step.key
	if strings.Contains(key, ",") {
		key = "(" + key + ")"
	}
	q := `DELETE FROM ` + step.table + ` WHERE ` + key + ` IN (SELECT ` + step.key + ` FROM ` + step.table + ` WHERE ` + step.scope + ` LIMIT ` + fmt.Sprint(purgeBatch) + `)`
	args := make([]any, strings.Count(step.scope, "?"))
	for i := range args {
		args[i] = org
	}
	var total int64
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return total, err
		}
		res, err := tx.ExecContext(ctx, q, args...)
		var n int64
		if err == nil {
			n, _ = res.RowsAffected()
			if progress != "" && n > 0 {
				_, err = tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(server_settings.value AS BIGINT)+? AS TEXT)`, progress, strconv.FormatInt(n, 10), time.Now().UTC().Format(time.RFC3339), n)
			}
		}
		if err == nil {
			err = purgeBatchHook(step.table)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
			return total, err
		}
		total += n
		if n < int64(purgeBatch) {
			return total, nil
		}
	}
}

// purgeBatchHook lets a test kill a purge between batches.
var purgeBatchHook = func(string) error { return nil }
