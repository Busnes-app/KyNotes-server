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
type ObjectStores func(org string) (*blobstore.Objects, error)

// objectGCBatch caps one pass (spec, Blobs in S3-compatible storage: Delete).
const objectGCBatch = 100

// orgUnreferenced is unreferenced for one org's blob b: in multi mode a digest is per org (N8).
const orgUnreferenced = `NOT EXISTS(SELECT 1 FROM object_versions v WHERE v.org_id=b.org_id AND v.blob_digest=b.digest) AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.org_id=b.org_id AND c.blob_digest=b.digest AND c.resolved_at='') AND NOT EXISTS(SELECT 1 FROM attachments a WHERE a.org_id=b.org_id AND (a.blob_digest=b.digest OR a.preview_digest=b.digest) AND (a.deleted_at='' OR EXISTS(SELECT 1 FROM attachment_refs r WHERE r.attachment_id=a.id)))`

// BlobLockName is the org-and-digest session lock (N3) every save, claim and delete of one
// object takes around its I/O and short write transaction.
func BlobLockName(org, digest string) string { return "blob/" + org + "/" + digest }

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
	return deleted, sweepErr
}

func sweepObject(ctx context.Context, db *sql.DB, stores ObjectStores, org, digest, cut string) (bool, error) {
	store, err := stores(org)
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
