package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"io"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ponytail: one process-wide upload lock; upgrade to per-upload locks if concurrent upload throughput matters.
var uploadMu sync.Mutex

func UploadRoutes(mux *http.ServeMux, db *sql.DB, blobs *blobstore.Store, cfg config.Config) {
	mux.Handle("GET /api/v1/uploads/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("ups", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var uid, status, expires string
		var received, next int64
		if e := db.QueryRow(`SELECT user_id,status,received_bytes,next_chunk,expires_at FROM upload_sessions WHERE id=?`, r.PathValue("id")).Scan(&uid, &status, &received, &next, &expires); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		writeJSON(w, map[string]any{"uploadId": r.PathValue("id"), "status": status, "receivedBytes": received, "nextChunk": next, "expiresAt": expires})
	})))
	mux.Handle("DELETE /api/v1/uploads/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("ups", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var uid string
		if e := db.QueryRow(`SELECT user_id FROM upload_sessions WHERE id=?`, id).Scan(&uid); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if t, e := blobs.Reopen(id); e == nil {
			_ = t.Abort()
		}
		_, _ = db.Exec(`UPDATE upload_sessions SET status='failed',updated_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), id)
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("HEAD /api/v1/containers/{id}/attachments/by-digest/{digest}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("cnt", r.PathValue("id")) != nil || len(r.PathValue("digest")) != 64 || !isHex(r.PathValue("digest")) {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var n int
		if e := db.QueryRow(`SELECT COUNT(*) FROM blob_containers bc JOIN memberships m ON m.container_id=bc.container_id AND m.user_id=? WHERE bc.container_id=? AND bc.digest=? AND m.revoked_at=''`, s.UserID, r.PathValue("id"), r.PathValue("digest")).Scan(&n); e != nil || n == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		w.WriteHeader(http.StatusOK)
	})))
	mux.Handle("POST /api/v1/containers/{id}/uploads", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		var role string
		if ids.Validate("cnt", cid) != nil || db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		var in struct {
			DeclaredBytes  int64  `json:"declaredBytes"`
			ExpectedDigest string `json:"expectedDigest"`
			Kind           string `json:"kind"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Kind != "attachment" && in.Kind != "preview") || in.DeclaredBytes < 0 || in.DeclaredBytes > cfg.Limits.AttachmentMaxBytes || (in.ExpectedDigest != "" && (len(in.ExpectedDigest) != 64 || !isHex(in.ExpectedDigest))) {
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		quota := cfg.Limits.UserQuotaBytes
		var configured int64
		_ = db.QueryRow(`SELECT quota_bytes FROM users WHERE id=?`, s.UserID).Scan(&configured)
		if configured > 0 {
			quota = configured
		}
		if quota > 0 && quotaUsage(db, s.UserID)+in.DeclaredBytes > quota {
			WriteError(w, r, 413, "quota_exceeded", "quota exceeded")
			return
		}
		var fs syscall.Statfs_t
		if syscall.Statfs(cfg.DataDir, &fs) == nil && uint64(fs.Bavail)*uint64(fs.Bsize) < uint64(2*cfg.Limits.AttachmentMaxBytes) {
			WriteError(w, r, 503, "unavailable", "storage unavailable")
			return
		}
		id, _ := ids.Mint("ups")
		now := time.Now().UTC()
		ttl := uploadTTL(cfg)
		if _, e := db.Exec(`INSERT INTO upload_sessions(id,user_id,container_id,kind,declared_bytes,chunk_bytes,expected_digest,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, s.UserID, cid, in.Kind, in.DeclaredBytes, cfg.Limits.ChunkBytes, in.ExpectedDigest, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339)); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		tmp, e := blobs.NewTemp(id)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		_ = tmp.Close()
		writeJSON(w, map[string]any{"uploadId": id, "chunkBytes": cfg.Limits.ChunkBytes, "expiresAt": now.Add(ttl).UTC().Format(time.RFC3339), "nextChunk": 0})
	})))
	mux.Handle("PATCH /api/v1/uploads/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadMu.Lock()
		defer uploadMu.Unlock()
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("ups", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var uid string
		var received, next, declared, chunk int64
		var expires, status string
		if e := db.QueryRow(`SELECT user_id,received_bytes,next_chunk,declared_bytes,chunk_bytes,expires_at,status FROM upload_sessions WHERE id=?`, id).Scan(&uid, &received, &next, &declared, &chunk, &expires, &status); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if status != "pending" || time.Now().After(parseTime(expires)) {
			WriteError(w, r, 410, "gone", "upload session expired")
			return
		}
		idx, e := strconv.ParseInt(r.Header.Get("X-Kynotes-Chunk-Index"), 10, 64)
		if e != nil || idx < 0 {
			WriteError(w, r, 400, "invalid_request", "invalid chunk index")
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, chunk+1))
		if e != nil || int64(len(body)) > chunk {
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		if idx < next {
			if idx != next-1 {
				writeUploadConflict(w, r, next)
				return
			}
			expected := declared - idx*chunk
			if expected > chunk {
				expected = chunk
			}
			tmp, openErr := blobs.Reopen(id)
			if openErr != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			previous := make([]byte, expected)
			readN, readErr := tmp.ReadAt(previous, idx*chunk)
			_ = tmp.Close()
			if readErr != nil && readN != len(previous) || !bytes.Equal(body, previous) {
				writeUploadConflict(w, r, next)
				return
			}
			writeJSON(w, map[string]any{"receivedBytes": received, "nextChunk": next})
			return
		}
		if idx != next {
			writeUploadConflict(w, r, next)
			return
		}
		if int64(len(body)) == 0 || received+int64(len(body)) > declared || (received+int64(len(body)) < declared && int64(len(body)) != chunk) {
			_, _ = db.Exec(`UPDATE upload_sessions SET status='failed' WHERE id=?`, id)
			if doomed, openErr := blobs.Reopen(id); openErr == nil {
				_ = doomed.Abort()
			}
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		tmp, e := blobs.Reopen(id)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		n, e := io.Copy(tmp, bytes.NewReader(body))
		_ = tmp.Close()
		if e != nil || n > chunk || received+n > declared || (received+n < declared && n != chunk) {
			_, _ = db.Exec(`UPDATE upload_sessions SET status='failed' WHERE id=?`, id)
			if doomed, openErr := blobs.Reopen(id); openErr == nil {
				_ = doomed.Abort()
			}
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		now := time.Now().UTC()
		_, e = db.Exec(`UPDATE upload_sessions SET received_bytes=received_bytes+?,next_chunk=next_chunk+1,updated_at=?,expires_at=? WHERE id=?`, n, now.Format(time.RFC3339), now.Add(uploadTTL(cfg)).Format(time.RFC3339), id)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"receivedBytes": received + n, "nextChunk": next + 1})
	})))
	mux.Handle("POST /api/v1/uploads/{id}/finalize", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("ups", id) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var uid, cid, kind, expected, status string
		var received, declared int64
		if e := db.QueryRow(`SELECT user_id,container_id,kind,expected_digest,received_bytes,declared_bytes,status FROM upload_sessions WHERE id=?`, id).Scan(&uid, &cid, &kind, &expected, &received, &declared, &status); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if status != "pending" {
			WriteError(w, r, 410, "gone", "upload session expired")
			return
		}
		if received != declared {
			WriteError(w, r, 422, "digest_mismatch", "ciphertext size mismatch")
			return
		}
		quota := cfg.Limits.UserQuotaBytes
		var configured int64
		_ = db.QueryRow(`SELECT quota_bytes FROM users WHERE id=?`, s.UserID).Scan(&configured)
		if configured > 0 {
			quota = configured
		}
		if quota > 0 && quotaUsage(db, s.UserID)+received > quota {
			_, _ = db.Exec(`UPDATE upload_sessions SET status='failed' WHERE id=?`, id)
			if doomed, openErr := blobs.Reopen(id); openErr == nil {
				_ = doomed.Abort()
			}
			WriteError(w, r, 413, "quota_exceeded", "quota exceeded")
			return
		}
		var in struct {
			MetadataCiphertext string `json:"metadataCiphertext"`
			KeyGeneration      int64  `json:"keyGeneration"`
			PreviewUploadID    string `json:"previewUploadId"`
		}
		if kind != "preview" {
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				WriteError(w, r, 400, "invalid_request", "invalid request")
				return
			}
			var generation int64
			if db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation) != nil || in.KeyGeneration != generation {
				WriteError(w, r, 409, "already_exists", "key rotation incomplete")
				return
			}
			var missing int
			if db.QueryRow(`SELECT COUNT(*) FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' WHERE d.revoked_at='' AND NOT EXISTS(SELECT 1 FROM key_envelopes e WHERE e.container_id=? AND e.device_id=d.id AND e.key_generation=?)`, cid, cid, generation).Scan(&missing) != nil || missing > 0 {
				WriteError(w, r, 409, "already_exists", "key rotation incomplete")
				return
			}
			meta, decodeErr := base64.StdEncoding.DecodeString(in.MetadataCiphertext)
			if decodeErr != nil || len(meta) > 4096 {
				WriteError(w, r, 400, "invalid_request", "invalid request")
				return
			}
			if in.PreviewUploadID != "" {
				var previewDigest string
				if db.QueryRow(`SELECT finalized_digest FROM upload_sessions WHERE id=? AND user_id=? AND container_id=? AND kind='preview' AND status='finalized'`, in.PreviewUploadID, s.UserID, cid).Scan(&previewDigest) != nil || previewDigest == "" {
					WriteError(w, r, 404, "not_found", "not found")
					return
				}
			}
		}
		tmp, e := blobs.Reopen(id)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		digest, size, e := tmp.Finalize(expected)
		if e != nil {
			_, _ = db.Exec(`UPDATE upload_sessions SET status='failed' WHERE id=?`, id)
			WriteError(w, r, 422, "digest_mismatch", "ciphertext digest mismatch")
			return
		}
		if kind == "preview" {
			now := time.Now().UTC().Format(time.RFC3339)
			e = dbTx(db, func(tx *sql.Tx) error {
				if _, e := tx.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,?) ON CONFLICT(digest) DO NOTHING`, digest, size, now); e != nil {
					return e
				}
				if _, e := tx.Exec(`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES(?,?,?) ON CONFLICT DO NOTHING`, digest, cid, now); e != nil {
					return e
				}
				_, e := tx.Exec(`UPDATE upload_sessions SET status='finalized',finalized_at=?,finalized_digest=?,updated_at=? WHERE id=?`, now, digest, now, id)
				return e
			})
			if e != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			writeJSON(w, map[string]any{"previewDigest": digest, "bytes": size})
			return
		}
		meta, decodeErr := base64.StdEncoding.DecodeString(in.MetadataCiphertext)
		if decodeErr != nil || len(meta) > 4096 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		att, _ := ids.Mint("att")
		now := time.Now().UTC().Format(time.RFC3339)
		previewDigest := ""
		if in.PreviewUploadID != "" {
			_ = db.QueryRow(`SELECT finalized_digest FROM upload_sessions WHERE id=? AND user_id=? AND container_id=? AND kind='preview' AND status='finalized'`, in.PreviewUploadID, s.UserID, cid).Scan(&previewDigest)
		}
		e = dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,?) ON CONFLICT(digest) DO NOTHING`, digest, size, now); e != nil {
				return e
			}
			if _, e := tx.Exec(`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES(?,?,?) ON CONFLICT DO NOTHING`, digest, cid, now); e != nil {
				return e
			}
			var changeSeq int64
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&changeSeq); e != nil {
				return e
			}
			if _, e := tx.Exec(`INSERT INTO attachments(id,container_id,blob_digest,preview_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, att, cid, digest, previewDigest, size, meta, in.KeyGeneration, changeSeq, now); e != nil {
				if scanErr := tx.QueryRow(`SELECT id FROM attachments WHERE container_id=? AND blob_digest=?`, cid, digest).Scan(&att); scanErr != nil {
					return e
				}
			}
			_, e = tx.Exec(`UPDATE upload_sessions SET status='finalized',finalized_at=?,finalized_digest=?,updated_at=? WHERE id=?`, now, digest, now, id)
			return e
		})
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"attachmentId": att, "digest": digest, "bytes": size})
	})))
	mux.Handle("GET /api/v1/attachments/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("att", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var digest string
		if e := db.QueryRow(`SELECT a.blob_digest FROM attachments a JOIN memberships m ON m.container_id=a.container_id AND m.user_id=? WHERE a.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&digest); e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		f, _, e := blobs.Open(digest)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "", time.Time{}, f)
	})))
	mux.Handle("GET /api/v1/attachments/{id}/preview", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("att", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var digest string
		if e := db.QueryRow(`SELECT a.preview_digest FROM attachments a JOIN memberships m ON m.container_id=a.container_id AND m.user_id=? WHERE a.id=? AND a.preview_digest!='' AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&digest); e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		f, _, e := blobs.Open(digest)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "", time.Time{}, f)
	})))
	mux.Handle("GET /api/v1/objects/{id}/attachments", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		rows, e := db.Query(`SELECT a.id,a.ciphertext_bytes,a.metadata_ciphertext,a.key_generation FROM attachments a JOIN attachment_refs ar ON ar.attachment_id=a.id JOIN objects o ON o.id=ar.object_id JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at='' AND a.deleted_at='' ORDER BY ar.created_at`, s.UserID, r.PathValue("id"))
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id string
			var bytes, generation int64
			var meta []byte
			if rows.Scan(&id, &bytes, &meta, &generation) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "bytes": bytes, "metadataCiphertext": base64.StdEncoding.EncodeToString(meta), "keyGeneration": generation})
		}
		writeJSON(w, out)
	})))
	mux.Handle("POST /api/v1/objects/{id}/attachments", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			AttachmentID  string `json:"attachmentId"`
			ObjectVersion int64  `json:"objectVersion"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if ids.Validate("obj", r.PathValue("id")) != nil || ids.Validate("att", in.AttachmentID) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var cid string
		if db.QueryRow(`SELECT o.container_id FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&cid) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		result, e := db.Exec(`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) SELECT id,?,?,? FROM attachments WHERE id=? AND container_id=?`, r.PathValue("id"), in.ObjectVersion, time.Now().UTC().Format(time.RFC3339), in.AttachmentID, cid)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if n, _ := result.RowsAffected(); n != 1 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("DELETE /api/v1/objects/{id}/attachments/{attachmentId}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("obj", r.PathValue("id")) != nil || ids.Validate("att", r.PathValue("attachmentId")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var n int
		if db.QueryRow(`SELECT COUNT(*) FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&n) != nil || n == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		_, _ = db.Exec(`DELETE FROM attachment_refs WHERE object_id=? AND attachment_id=?`, r.PathValue("id"), r.PathValue("attachmentId"))
		w.WriteHeader(http.StatusNoContent)
	})))
}

func writeUploadConflict(w http.ResponseWriter, r *http.Request, next int64) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "already_exists", "message": "unexpected chunk", "requestId": w.Header().Get("X-Request-Id")}, "nextChunk": next})
}
func parseTime(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
func quotaUsage(db *sql.DB, userID string) int64 {
	var n sql.NullInt64
	_ = db.QueryRow(`SELECT COALESCE((SELECT SUM(v.ciphertext_bytes) FROM object_versions v JOIN objects o ON o.id=v.object_id JOIN containers c ON c.id=o.container_id WHERE c.owner_user_id=?),0)+(SELECT COALESCE(SUM(c.ciphertext_bytes),0) FROM conflicts c JOIN containers x ON x.id=c.container_id WHERE x.owner_user_id=?)+(SELECT COALESCE(SUM(a.ciphertext_bytes),0) FROM attachments a JOIN containers x ON x.id=a.container_id WHERE x.owner_user_id=? AND a.deleted_at='')`, userID, userID, userID).Scan(&n)
	return n.Int64
}

func uploadTTL(cfg config.Config) time.Duration {
	ttl, err := time.ParseDuration(cfg.Limits.UploadSessionTTL)
	if err != nil || ttl <= 0 {
		return 15 * time.Minute
	}
	return ttl
}
