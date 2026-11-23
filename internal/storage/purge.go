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
	{"org_pool", "org_id", "org_id=?"},
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

const (
	ownedContainers = `(SELECT id FROM containers WHERE owner_user_id=?)`
	ownedObjects    = `(SELECT o.id FROM objects o JOIN containers c ON c.id=o.container_id WHERE c.owner_user_id=?)`
)

// eraseSteps are steps 4 and 5 of a member's Delete everything, by the member's ID: the
// notebooks it still owns (no other approved member took them over), children first, then its
// rows elsewhere. Its comments in notebooks others keep become tombstones, and its user row is
// scrubbed and kept (owner decision 12, eraseMember), since comments cascade from it.
var eraseSteps = []purgeStep{
	{"activity", "id", "container_id IN " + ownedContainers},
	{"share_links", "id", "object_id IN " + ownedObjects},
	{"attachment_refs", "attachment_id,object_id,object_version", "object_id IN " + ownedObjects},
	{"mentions", "comment_id,mentioned_user_id", "comment_id IN (SELECT id FROM comments WHERE container_id IN " + ownedContainers + ")"},
	{"comments", "id", "container_id IN " + ownedContainers},
	{"conflicts", "id", "container_id IN " + ownedContainers},
	{"object_versions", "object_id,version", "object_id IN " + ownedObjects},
	{"attachments", "id", "container_id IN " + ownedContainers},
	{"upload_sessions", "id", "container_id IN " + ownedContainers},
	{"objects", "id", "container_id IN " + ownedContainers},
	{"invitation_envelopes", "invitation_id,container_id", "container_id IN " + ownedContainers},
	{"invitations", "id", "container_id IN " + ownedContainers},
	{"key_envelopes", "id", "container_id IN " + ownedContainers},
	{"device_containers", "device_id,container_id", "container_id IN " + ownedContainers},
	{"blob_containers", "digest,container_id", "container_id IN " + ownedContainers},
	{"memberships", "id", "container_id IN " + ownedContainers},
	{"containers", "id", "owner_user_id=?"},
	{"mentions", "comment_id,mentioned_user_id", "mentioned_user_id=? OR comment_id IN (SELECT id FROM comments WHERE author_user_id=?)"},
	{"reminders", "id", "user_id=?"},
	{"web_push_subscriptions", "id", "user_id=?"},
	{"sealed_share_links", "id", "owner_user_id=?"},
	{"upload_sessions", "id", "user_id=?"},
	{"pairing_nonces", "nonce", "user_id=?"}, // no foreign key, so not in the user's cascade
	// The directory's fences for the subject; erased_subjects alone now refuses its sign-in.
	{"sso_directory_state", "issuer,subject", "(issuer,subject) IN (SELECT sso_issuer,sso_subject FROM users WHERE id=? AND sso_subject<>'')"},
	{"sso_login_cutoffs", "issuer,subject", "(issuer,subject) IN (SELECT sso_issuer,sso_subject FROM users WHERE id=? AND sso_subject<>'')"},
	{"link_requests", "id", "user_id=?"},
	{"sso_stepup", "id", "session_id IN (SELECT id FROM sessions WHERE user_id=?)"},
	{"sessions", "id", "user_id=?"},
	{"push_registrations", "device_id", "device_id IN (SELECT id FROM devices WHERE user_id=?)"},
	{"key_envelopes", "id", "device_id IN (SELECT id FROM devices WHERE user_id=?)"},
	{"device_containers", "device_id,container_id", "device_id IN (SELECT id FROM devices WHERE user_id=?)"},
	{"invitation_envelopes", "invitation_id,container_id", "device_id IN (SELECT id FROM devices WHERE user_id=?)"},
	{"user_identities", "user_id", "user_id=?"},
	{"devices", "id", "user_id=?"},
	{"memberships", "id", "user_id=?"},
}

// EraseMembers finishes every Delete everything begun by a user.erased event (users with status
// erased), in batches, resumably: a worker killed between batches finishes on its next run.
// Multi mode only. Pages the member wrote in notebooks others keep stay: they are the team's.
func EraseMembers(ctx context.Context, db *sql.DB) error {
	tenancy, err := TenancyOf(db)
	if err != nil || !tenancy.Multi() {
		return err
	}
	// A scrubbed account (its username is its ID) is done; the rest resume.
	rows, err := db.QueryContext(ctx, `SELECT id FROM users WHERE status='erased' AND username<>id`)
	if err != nil {
		return err
	}
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		users = append(users, id)
	}
	rows.Close()
	for _, user := range users {
		for _, step := range eraseSteps {
			if _, err := purgeTable(ctx, db, step, user, ""); err != nil {
				return fmt.Errorf("erase %s: %w", step.table, err)
			}
		}
		if err := eraseMember(ctx, db, user); err != nil {
			return err
		}
		if err := RecordAuditOutcome(db, "", "platform.member_erased", "", "", "success", "", "member-erase"); err != nil {
			return err
		}
	}
	return rows.Err()
}

// eraseMember tombstones the member's comments in notebooks others keep, in batches (ciphertext
// cleared, as a comment deletion does), each at a fresh change sequence of its notebook so every
// device syncs the deletion. Then it scrubs the user row down to its random ID: no name, secret,
// salt, recovery or SSO binding is left (owner decision 12). erased_subjects keeps the subject,
// so it can never sign in again. The cleanup backend preserves SQLite's reserved row space
// when tests exercise the same path there; production multi mode uses PostgreSQL.
func eraseMember(ctx context.Context, db *sql.DB, user string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	for {
		n, err := tombstoneBatch(ctx, db, user, now)
		if err != nil {
			return err
		}
		if n < purgeBatch {
			break
		}
	}
	_, err := db.ExecContext(ctx, `UPDATE users SET username=id,auth_secret_hash='',login_salt='',recovery_hash='',recovery_used_at='',sso_subject='',sso_issuer='',password_admin_known=0,role='user',updated_at=? WHERE id=? AND status='erased'`, now, user)
	return err
}

// tombstoneBatch tombstones up to purgeBatch of the member's live comments in one transaction.
func tombstoneBatch(ctx context.Context, db *sql.DB, user, now string) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,container_id FROM comments WHERE author_user_id=? AND deleted_at='' LIMIT `+fmt.Sprint(purgeBatch), user)
	if err != nil {
		return 0, err
	}
	var batch [][2]string
	for rows.Next() {
		var c [2]string
		if err := rows.Scan(&c[0], &c[1]); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, c := range batch {
		// One sequence per comment: sync pages by change_seq, so rows must not share one.
		seq, err := CleanupFor(db).AdvanceSeq(tx, c[1], now)
		if err != nil {
			return 0, err
		}
		if err := CleanupFor(db).TombstoneComment(tx, c[0], now, seq); err != nil {
			return 0, err
		}
	}
	return len(batch), tx.Commit()
}
