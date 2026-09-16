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
	if !blobsEnabled {
		return st, nil
	}
	cut := now.Add(-retention).UTC().Format(time.RFC3339)
	rows, e = db.Query(`SELECT b.digest FROM blobs b WHERE b.unreferenced_since!='' AND b.unreferenced_since<? AND NOT EXISTS(SELECT 1 FROM object_versions v WHERE v.blob_digest=b.digest) AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.blob_digest=b.digest AND c.resolved_at='') AND NOT EXISTS(SELECT 1 FROM attachments a WHERE (a.blob_digest=b.digest OR a.preview_digest=b.digest) AND a.deleted_at='')`, cut)
	if e != nil {
		return st, e
	}
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			if e := blobs.Delete(d); e != nil {
				continue
			}
			_, _ = db.Exec(`DELETE FROM blob_containers WHERE digest=?`, d)
			_, _ = db.Exec(`DELETE FROM blobs WHERE digest=?`, d)
			st.DeletedBlobs++
		}
	}
	rows.Close()
	_, e = db.Exec(`UPDATE blobs SET unreferenced_since=? WHERE unreferenced_since='' AND NOT EXISTS(SELECT 1 FROM object_versions v WHERE v.blob_digest=blobs.digest) AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.blob_digest=blobs.digest AND c.resolved_at='') AND NOT EXISTS(SELECT 1 FROM attachments a WHERE (a.blob_digest=blobs.digest OR a.preview_digest=blobs.digest) AND a.deleted_at='')`, now.UTC().Format(time.RFC3339))
	return st, e
}
