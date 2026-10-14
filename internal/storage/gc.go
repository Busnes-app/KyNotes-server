package storage

import (
	"database/sql"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"time"
)

type GCStats struct{ ExpiredUploads, DeletedBlobs int }

func RunGC(db *sql.DB, blobs *blobstore.Store, now time.Time, retention time.Duration, blobsEnabled bool) (GCStats, error) {
	var st GCStats
	rows, e := db.Query(`SELECT id FROM upload_sessions WHERE status='pending' AND expires_at<?`, now.UTC().Format(time.RFC3339))
	if e != nil {
		return st, e
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			if t, e := blobs.Reopen(id); e == nil {
				_ = t.Abort()
			}
			_, _ = db.Exec(`UPDATE upload_sessions SET status='expired',updated_at=? WHERE id=?`, now.UTC().Format(time.RFC3339), id)
			st.ExpiredUploads++
		}
	}
	rows.Close()
	_, _ = db.Exec(`DELETE FROM upload_sessions WHERE status='expired' AND updated_at<?`, now.Add(-24*time.Hour).UTC().Format(time.RFC3339))
	_, _ = db.Exec(`DELETE FROM sessions WHERE (revoked_at!='' AND revoked_at<?) OR hard_expires_at<?`, now.Add(-24*time.Hour).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	_, _ = db.Exec(`DELETE FROM idempotency_keys WHERE created_at<?`, now.Add(-24*time.Hour).UTC().Format(time.RFC3339))
	// An expired invitation can never be accepted; its envelopes are dead weight.
	_, _ = db.Exec(`DELETE FROM invitation_envelopes WHERE invitation_id IN (SELECT id FROM invitations WHERE status='pending' AND expires_at<=?)`, now.UTC().Format(time.RFC3339))
	// An expired link request can never complete.
	_, _ = db.Exec(`DELETE FROM link_requests WHERE expires_at<=?`, now.UTC().Format(time.RFC3339))
	if !blobsEnabled {
		return st, nil
	}
	cut := now.Add(-retention).UTC().Format(time.RFC3339)
	rows, e = db.Query(`SELECT digest FROM blobs b WHERE unreferenced_since!='' AND unreferenced_since<? AND `+unreferenced, cut)
	if e != nil {
		return st, e
	}
	var digests []string
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			digests = append(digests, d)
		}
	}
	rows.Close()
	var sweepErr error
	for _, d := range digests {
		deleted, e := sweepBlob(db, blobs, d, cut)
		if deleted {
			st.DeletedBlobs++
		}
		if sweepErr == nil {
			sweepErr = e
		}
	}
	if _, e = db.Exec(`UPDATE blobs AS b SET unreferenced_since='' WHERE unreferenced_since!='' AND NOT (` + unreferenced + `)`); e != nil {
		return st, e
	}
	if _, e = db.Exec(`UPDATE blobs AS b SET unreferenced_since=? WHERE unreferenced_since='' AND `+unreferenced, now.UTC().Format(time.RFC3339)); e != nil {
		return st, e
	}
	return st, sweepErr
}

// unreferenced holds for blob b with no version, open conflict, or live or linked attachment.
const unreferenced = `NOT EXISTS(SELECT 1 FROM object_versions v WHERE v.blob_digest=b.digest) AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.blob_digest=b.digest AND c.resolved_at='') AND NOT EXISTS(SELECT 1 FROM attachments a WHERE (a.blob_digest=b.digest OR a.preview_digest=b.digest) AND (a.deleted_at='' OR EXISTS(SELECT 1 FROM attachment_refs r WHERE r.attachment_id=a.id)))`

// sweepBlob re-checks d and deletes its file inside the write transaction that drops its row.
// Writers check the file inside theirs (claimBlob), so a save either commits first and keeps
// the blob, or finds the file gone and fails. A crash before commit leaves an unreferenced row
// without a file, which the next sweep removes.
func sweepBlob(db *sql.DB, blobs *blobstore.Store, d, cut string) (bool, error) {
	tx, e := db.Begin()
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRow(`SELECT COUNT(*) FROM blobs b WHERE digest=? AND unreferenced_since!='' AND unreferenced_since<? AND `+unreferenced, d, cut).Scan(&n); e != nil || n == 0 {
		return false, e
	}
	// Tombstones older than the mark still hold the blob's foreign key.
	for _, q := range []string{
		`DELETE FROM attachments WHERE blob_digest=? AND deleted_at!=''`,
		`DELETE FROM conflicts WHERE blob_digest=? AND resolved_at!=''`,
		`DELETE FROM blob_containers WHERE digest=?`,
		`DELETE FROM blobs WHERE digest=?`,
	} {
		if _, e = tx.Exec(q, d); e != nil {
			return false, e
		}
	}
	if e = blobs.Delete(d); e != nil {
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	return true, nil
}
