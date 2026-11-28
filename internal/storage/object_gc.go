package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

// ObjectStores resolves one org's primary-object store. Only the elected multi-mode worker
// calls it, with org IDs read from blob rows.
type ObjectStores func(ctx context.Context, org string) (*blobstore.Objects, error)

// CellObjectStores opens each org's store under its cell, the org's mirrored home_region
// (Cells: orgs never move), so purge, GC and the orphan sweep stay in the org's own prefix.
func CellObjectStores(db *sql.DB, open func(cell, org string) (*blobstore.Objects, error)) ObjectStores {
	return func(ctx context.Context, org string) (*blobstore.Objects, error) {
		var cell string
		if err := db.QueryRowContext(ctx, `SELECT home_region FROM orgs WHERE id=?`, org).Scan(&cell); err != nil {
			return nil, err
		}
		return open(cell, org)
	}
}

// objectGCBatch caps one pass (spec, Blobs in S3-compatible storage: Delete).
const objectGCBatch = 100

// orgUnreferenced is unreferenced for one org's blob b: in multi mode a digest is per org (N8).
const orgUnreferenced = `NOT EXISTS(SELECT 1 FROM object_versions v WHERE v.org_id=b.org_id AND v.blob_digest=b.digest) AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.org_id=b.org_id AND c.blob_digest=b.digest AND c.resolved_at='') AND NOT EXISTS(SELECT 1 FROM attachments a WHERE a.org_id=b.org_id AND (a.blob_digest=b.digest OR a.preview_digest=b.digest) AND (a.deleted_at='' OR EXISTS(SELECT 1 FROM attachment_refs r WHERE r.attachment_id=a.id)))`

// BlobLockName is the org-and-digest session lock (N3) every save, claim and delete of one
// object takes around its I/O and short write transaction.
func BlobLockName(org, digest string) string { return "blob/" + org + "/" + digest }

// UploadLockName is shared by object upload requests and the orphan sweep.
func UploadLockName(org, id string) string { return "upload/" + org + "/" + id }

// RunObjectGC is RunGC's blob sweep for multi mode, where blobs live in object storage keyed
// by org. Each blob is re-checked and its rows deleted under its session lock, committed, and
// only then is the object deleted, still under the lock. A delete that fails after the commit
// leaves an object with no row; that costs storage only.
func RunObjectGC(ctx context.Context, db *sql.DB, stores ObjectStores, now time.Time, retention time.Duration) (int, error) {
	tenancy, err := TenancyOfContext(ctx, db)
	if err != nil {
		return 0, err
	}
	if !tenancy.Multi() || !IsPostgres(db) {
		return 0, errors.New("object gc: multi mode on PostgreSQL only")
	}
	cut := now.Add(-retention).UTC().Format(time.RFC3339)
	rows, err := db.QueryContext(ctx, `SELECT org_id,digest FROM blobs b WHERE unreferenced_since!='' AND unreferenced_since<? AND `+OrgServes("b.org_id")+` AND `+orgUnreferenced+` ORDER BY unreferenced_since,org_id,digest LIMIT ?`, cut, objectGCBatch)
	if err != nil {
		return 0, err
	}
	type blob struct{ org, digest string }
	var due []blob
	for rows.Next() {
		var b blob
		if err := rows.Scan(&b.org, &b.digest); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	deleted := 0
	var sweepErr error
	for _, b := range due {
		ok, err := sweepObject(ctx, db, stores, b.org, b.digest, cut)
		if ok {
			deleted++
		}
		sweepErr = errors.Join(sweepErr, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE blobs AS b SET unreferenced_since='' WHERE unreferenced_since!='' AND NOT (`+orgUnreferenced+`)`); err != nil {
		return deleted, errors.Join(sweepErr, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE blobs AS b SET unreferenced_since=? WHERE unreferenced_since='' AND `+orgUnreferenced, now.UTC().Format(time.RFC3339)); err != nil {
		return deleted, errors.Join(sweepErr, err)
	}
	orphans, err := SweepOrphanObjects(ctx, db, stores)
	return deleted + orphans, errors.Join(sweepErr, err)
}

// orphanAge is how old, by the provider's clock, an object no row claims must be before the
// sweep deletes it (spec: an hour). It exceeds LatePutWindow, so no admitted PUT is in flight.
const orphanAge = time.Hour

// SweepOrphanObjects deletes serving orgs' objects that no row claims: a blob whose delete
// failed after its commit, or one a late PUT wrote after GC or an erasure deleted it, and the
// parts of an upload with no pending session. Each deletion is admitted under its session lock
// (the org still serves, no claim), so a writer that holds the lock claims first and an org
// stopped after the listing keeps its objects. Unknown provider age never deletes.
func SweepOrphanObjects(ctx context.Context, db *sql.DB, stores ObjectStores) (int, error) {
	var now int64
	if err := db.QueryRowContext(ctx, `SELECT floor(extract(epoch FROM clock_timestamp()))::bigint`).Scan(&now); err != nil {
		return 0, err
	}
	cutoff := time.Unix(now, 0).Add(-orphanAge)
	rows, err := db.QueryContext(ctx, `SELECT id FROM orgs o WHERE `+OrgServes("o.id")+` ORDER BY id`)
	if err != nil {
		return 0, err
	}
	var orgs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		orgs = append(orgs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	deleted := 0
	for _, org := range orgs {
		store, err := stores(ctx, org)
		if err != nil {
			return deleted, err
		}
		blobs, uploads, err := store.Stored(ctx)
		if err != nil {
			return deleted, err
		}
		type orphan struct {
			lock, claimed string
			id            string
			drop          func(context.Context, string) error
		}
		var due []orphan
		for digest, at := range blobs {
			if !at.IsZero() && at.Before(cutoff) {
				due = append(due, orphan{BlobLockName(org, digest), `SELECT count(*) FROM blobs WHERE org_id=? AND digest=?`, digest, store.Delete})
			}
		}
		for id, at := range uploads {
			if !at.IsZero() && at.Before(cutoff) {
				due = append(due, orphan{UploadLockName(org, id), `SELECT count(*) FROM upload_sessions WHERE org_id=? AND id=? AND status='pending'`, id, store.DeleteParts})
			}
		}
		for _, o := range due {
			if deleted >= objectGCBatch {
				return deleted, nil
			}
			ok, err := dropOrphan(ctx, db, org, o.lock, o.claimed, o.id, o.drop)
			if err != nil {
				return deleted, err
			}
			if ok {
				deleted++
			}
		}
	}
	return deleted, nil
}

func dropOrphan(ctx context.Context, db *sql.DB, org, lock, claimed, id string, drop func(context.Context, string) error) (bool, error) {
	lease, _, err := SessionLock(ctx, db, lock, true)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	// Admit under the lock, in a short transaction (N3) that serialises with the org poll's
	// status write: the org still serves and nothing claims the object. No I/O holds N3.
	tx, err := lease.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var serving, n int
	if err := tx.QueryRow(`SELECT count(*) FROM orgs o WHERE o.id=? AND `+OrgServes("o.id"), org).Scan(&serving); err != nil || serving == 0 {
		return false, err
	}
	if err := tx.QueryRow(claimed, org, id).Scan(&n); err != nil || n != 0 {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, drop(lease.Context, id)
}

func sweepObject(ctx context.Context, db *sql.DB, stores ObjectStores, org, digest, cut string) (bool, error) {
	store, err := stores(ctx, org)
	if err != nil {
		return false, err
	}
	lease, _, err := SessionLock(ctx, db, BlobLockName(org, digest), true)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	tx, err := lease.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM blobs b WHERE org_id=? AND digest=? AND unreferenced_since!='' AND unreferenced_since<? AND `+OrgServes("b.org_id")+` AND `+orgUnreferenced, org, digest, cut).Scan(&n); err != nil || n == 0 {
		return false, err
	}
	// Tombstones older than the mark still hold the blob's foreign key.
	for _, q := range []string{
		`DELETE FROM attachments WHERE org_id=? AND blob_digest=? AND deleted_at!=''`,
		`DELETE FROM conflicts WHERE org_id=? AND blob_digest=? AND resolved_at!=''`,
		`DELETE FROM blob_containers WHERE org_id=? AND digest=?`,
		`DELETE FROM blobs WHERE org_id=? AND digest=?`,
	} {
		if _, err := tx.Exec(q, org, digest); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, store.Delete(lease.Context, digest)
}

// RunObjectMaintenance retires expired uploads under the same org/upload lock used by
// requests. Commit the fence before deleting remote parts; a failed DELETE remains retryable.
func RunObjectMaintenance(ctx context.Context, db *sql.DB, stores ObjectStores, now time.Time) error {
	rows, err := db.QueryContext(ctx, `SELECT org_id,id FROM upload_sessions WHERE ((status='pending' AND expires_at<?) OR (status='failed' AND finalized_digest='')) AND `+OrgServes("org_id")+` ORDER BY org_id,id LIMIT 100`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	type upload struct{ org, id string }
	var due []upload
	for rows.Next() {
		var u upload
		if err := rows.Scan(&u.org, &u.id); err != nil {
			rows.Close()
			return err
		}
		due = append(due, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range due {
		if err := expireObjectUpload(ctx, db, stores, u.org, u.id, now); err != nil {
			return err
		}
	}
	// Same non-blob retention rules as the single-mode worker. No kept version is pruned.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM attachment_refs WHERE attachment_id IN (SELECT id FROM attachments WHERE container_id IN (SELECT id FROM containers WHERE deleted_at<>''))`,
		`UPDATE attachments SET deleted_at=(SELECT deleted_at FROM containers WHERE id=attachments.container_id) WHERE deleted_at='' AND container_id IN (SELECT id FROM containers WHERE deleted_at<>'')`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	at, cut := now.UTC().Format(time.RFC3339), now.Add(-24*time.Hour).UTC().Format(time.RFC3339)
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`DELETE FROM upload_sessions WHERE status='expired' AND updated_at<?`, []any{cut}},
		{`DELETE FROM sessions WHERE (revoked_at!='' AND revoked_at<?) OR hard_expires_at<?`, []any{cut, at}},
		{`DELETE FROM idempotency_keys WHERE created_at<?`, []any{cut}},
		{`DELETE FROM invitation_envelopes WHERE invitation_id IN (SELECT id FROM invitations WHERE status='pending' AND expires_at<=?)`, []any{at}},
		{`DELETE FROM link_requests WHERE expires_at<=?`, []any{at}},
		{`DELETE FROM sealed_share_links WHERE expires_at<=? OR revoked_at<>''`, []any{at}},
	} {
		if _, err := tx.ExecContext(ctx, stmt.q, stmt.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func expireObjectUpload(ctx context.Context, db *sql.DB, stores ObjectStores, org, id string, now time.Time) error {
	lease, _, err := SessionLock(ctx, db, UploadLockName(org, id), true)
	if err != nil {
		return err
	}
	defer lease.Release()
	tx, err := lease.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE upload_sessions SET status='failed',updated_at=? WHERE id=? AND org_id=? AND ((status='pending' AND expires_at<?) OR (status='failed' AND finalized_digest='')) AND `+OrgServes("org_id"), now.UTC().Format(time.RFC3339), id, org, now.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	store, err := stores(ctx, org)
	if err != nil {
		return err
	}
	if err := store.DeleteParts(lease.Context, id); err != nil {
		return err
	}
	_, err = lease.Exec(`UPDATE upload_sessions SET status='expired',updated_at=? WHERE id=? AND org_id=? AND status='failed'`, now.UTC().Format(time.RFC3339), id, org)
	return err
}
