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

// uploadMaxLifetime caps a session that keeps refreshing its inactivity expiry.
const uploadMaxLifetime = 24 * time.Hour

var (
	uploadLocksMu sync.Mutex
	uploadLocks   = map[string]*uploadLock{}
)

type uploadLock struct {
	sync.Mutex
	users int
}

// lockUpload serializes the chunks of one upload session; its entry goes once unused.
func lockUpload(id string) (unlock func()) {
	uploadLocksMu.Lock()
	l := uploadLocks[id]
	if l == nil {
		l = &uploadLock{}
		uploadLocks[id] = l
	}
	l.users++
	uploadLocksMu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		uploadLocksMu.Lock()
		if l.users--; l.users == 0 {
			delete(uploadLocks, id)
		}
		uploadLocksMu.Unlock()
	}
}

func UploadRoutes(mux RouteMux, db *sql.DB, blobs *blobstore.Store, cfg config.Config) {
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
		if _, err := checkContainerKeyed(db, cid, s.UserID, r.Header.Get(keySchemeHeader)); writeTeamKeyError(w, r, err) {
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
		if over, err := quotaExceeded(db, cfg.Limits, cid, "", in.DeclaredBytes); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		} else if over {
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
		var uid, cid string
		var received, next, declared, chunk int64
		var created, expires, status string
		const sessionSQL = `SELECT user_id,container_id,received_bytes,next_chunk,declared_bytes,chunk_bytes,created_at,expires_at,status FROM upload_sessions WHERE id=?`
		if e := db.QueryRow(sessionSQL, id).Scan(&uid, &cid, &received, &next, &declared, &chunk, &created, &expires, &status); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if writeTeamKeyError(w, r, checkUploader(db, cid, s.UserID, r.Header.Get(keySchemeHeader))) {
			return
		}
		idx, e := strconv.ParseInt(r.Header.Get("X-Kynotes-Chunk-Index"), 10, 64)
		if e != nil || idx < 0 {
			WriteError(w, r, 400, "invalid_request", "invalid chunk index")
			return
		}
		// Read before locking: a slow body must not stall other chunks.
		body, e := io.ReadAll(io.LimitReader(r.Body, chunk+1))
		if e != nil || int64(len(body)) > chunk {
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		defer lockUpload(id)()
		if e := db.QueryRow(sessionSQL, id).Scan(&uid, &cid, &received, &next, &declared, &chunk, &created, &expires, &status); e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		// A removal or demotion may have committed while the body streamed.
		if writeTeamKeyError(w, r, checkUploader(db, cid, s.UserID, r.Header.Get(keySchemeHeader))) {
			return
		}
		if !uploadLive(status, created, expires) {
			WriteError(w, r, 410, "gone", "upload session expired")
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
		var uid, cid, kind, expected, status, created, expires string
		var received, declared int64
		if e := db.QueryRow(`SELECT user_id,container_id,kind,expected_digest,received_bytes,declared_bytes,status,created_at,expires_at FROM upload_sessions WHERE id=?`, id).Scan(&uid, &cid, &kind, &expected, &received, &declared, &status, &created, &expires); e != nil || uid != s.UserID {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if writeTeamKeyError(w, r, checkUploader(db, cid, s.UserID, r.Header.Get(keySchemeHeader))) {
			return
		}
		if !uploadLive(status, created, expires) {
			WriteError(w, r, 410, "gone", "upload session expired")
			return
		}
		if received != declared {
			WriteError(w, r, 422, "digest_mismatch", "ciphertext size mismatch")
			return
		}
		over, err := quotaExceeded(db, cfg.Limits, cid, id, received)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if over {
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
			if writeTeamKeyError(w, r, checkWriteGate(db, cid, s.UserID, in.KeyGeneration, r.Header.Get(keySchemeHeader))) {
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
				if e := claimBlob(tx, blobs, digest, cid, size, now); e != nil {
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
			if e := checkWriteGate(tx, cid, s.UserID, in.KeyGeneration, r.Header.Get(keySchemeHeader)); e != nil {
				return e
			}
			if e := checkUploader(tx, cid, s.UserID, r.Header.Get(keySchemeHeader)); e != nil {
				return e
			}
			if e := claimBlob(tx, blobs, digest, cid, size, now); e != nil {
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
				// Re-uploading the bytes of a deleted attachment revives it; linking refuses tombstones.
				if _, e := tx.Exec(`UPDATE attachments SET deleted_at='' WHERE id=?`, att); e != nil {
					return e
				}
			}
			_, e = tx.Exec(`UPDATE upload_sessions SET status='finalized',finalized_at=?,finalized_digest=?,updated_at=? WHERE id=?`, now, digest, now, id)
			return e
		})
		if writeTeamKeyError(w, r, e) {
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
		var cid, role string
		if db.QueryRow(`SELECT o.container_id,m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&cid, &role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		result, e := db.Exec(`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) SELECT a.id,o.id,?,? FROM attachments a JOIN objects o ON o.id=? AND o.container_id=a.container_id AND o.deleted_at='' WHERE a.id=? AND a.container_id=? AND a.deleted_at=''`, in.ObjectVersion, time.Now().UTC().Format(time.RFC3339), r.PathValue("id"), in.AttachmentID, cid)
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
		var role string
		if db.QueryRow(`SELECT m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		if _, e := db.Exec(`DELETE FROM attachment_refs WHERE object_id=? AND attachment_id=?`, r.PathValue("id"), r.PathValue("attachmentId")); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
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

// checkUploader admits userID to send bytes into cid: checkContainerKeyed plus an owner, admin or editor role.
func checkUploader(q rowQuerier, cid, userID, scheme string) error {
	if _, err := checkContainerKeyed(q, cid, userID, scheme); err != nil {
		return err
	}
	var role string
	if err := q.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, userID).Scan(&role); err != nil {
		return err
	}
	if role != "owner" && role != "admin" && role != "editor" {
		return errInsufficientRole
	}
	return nil
}

func uploadLive(status, created, expires string) bool {
	now := time.Now()
	return status == "pending" && !now.After(parseTime(expires)) && !now.After(parseTime(created).Add(uploadMaxLifetime))
}

// quotaExceeded reports whether n more bytes in cid would exceed its owner's quota or, in a team,
// the team's (IMPLEMENTATION_PLAN.md 1.14). Live pending uploads other than skip count at their
// declared size.
func quotaExceeded(q rowQuerier, limits config.Limits, cid, skip string, n int64) (bool, error) {
	var owner, kind, team string
	var userQuota int64
	if err := q.QueryRow(`SELECT c.owner_user_id,c.kind,c.team_id,u.quota_bytes FROM containers c JOIN users u ON u.id=c.owner_user_id WHERE c.id=?`, cid).Scan(&owner, &kind, &team, &userQuota); err != nil {
		return false, err
	}
	if userQuota == 0 {
		userQuota = limits.UserQuotaBytes
	}
	if kind == "team" {
		team = cid
	}
	now := time.Now().UTC().Format(time.RFC3339)
	over := func(quota int64, scope, key string) (bool, error) {
		if quota <= 0 {
			return false, nil
		}
		var used int64
		err := q.QueryRow(`SELECT
 (SELECT COALESCE(SUM(v.ciphertext_bytes),0) FROM object_versions v JOIN objects o ON o.id=v.object_id WHERE o.container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM conflicts WHERE container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM attachments WHERE deleted_at='' AND container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(declared_bytes),0) FROM upload_sessions WHERE status='pending' AND expires_at>?2 AND id<>?3 AND container_id IN (`+scope+`))`, key, now, skip).Scan(&used)
		return used+n > quota, err
	}
	if exceeded, err := over(userQuota, `SELECT id FROM containers WHERE owner_user_id=?1`, owner); exceeded || err != nil {
		return exceeded, err
	}
	if team == "" {
		return false, nil
	}
	return over(limits.TeamQuotaBytes, `SELECT id FROM containers WHERE id=?1 OR team_id=?1`, team)
}

func uploadTTL(cfg config.Config) time.Duration {
	ttl, err := time.ParseDuration(cfg.Limits.UploadSessionTTL)
	if err != nil || ttl <= 0 {
		return 15 * time.Minute
	}
	return ttl
}
