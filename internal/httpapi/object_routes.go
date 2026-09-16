package httpapi

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"io"
	"net/http"
	"strconv"
	"time"
)

func commitReceipt(objectID, digest string, version, bytes, generation, baseVersion, changeSeq int64) string {
	h := sha256.New()
	_, _ = h.Write([]byte("kynotes-commit-receipt-v1\x00"))
	writeReceiptString := func(v string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(v))
	}
	writeReceiptInt := func(v int64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v))
		_, _ = h.Write(n[:])
	}
	writeReceiptString(objectID)
	writeReceiptInt(version)
	writeReceiptString(digest)
	writeReceiptInt(bytes)
	writeReceiptInt(generation)
	writeReceiptInt(baseVersion)
	writeReceiptInt(changeSeq)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func currentCommitReceipt(db *sql.DB, objectID string, version int64) string {
	var digest string
	var bytes, generation, baseVersion, changeSeq int64
	if db.QueryRow(`SELECT v.blob_digest,v.ciphertext_bytes,v.key_generation,v.base_version,v.change_seq FROM object_versions v WHERE v.object_id=? AND v.version=?`, objectID, version).Scan(&digest, &bytes, &generation, &baseVersion, &changeSeq) != nil {
		return ""
	}
	return commitReceipt(objectID, digest, version, bytes, generation, baseVersion, changeSeq)
}

func ObjectRoutes(mux *http.ServeMux, db *sql.DB, blobs *blobstore.Store, max int64) {
	mux.Handle("GET /api/v1/objects/{id}/conflicts", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		if ids.Validate("obj", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		rows, e := db.Query(`SELECT c.id,c.base_version,c.current_version,c.ciphertext_bytes,c.created_at,c.resolved_at FROM conflicts c JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? WHERE c.object_id=? AND m.revoked_at='' ORDER BY c.created_at`, uid, r.PathValue("id"))
		if e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, created, res string
			var base, cur, size int64
			_ = rows.Scan(&id, &base, &cur, &size, &created, &res)
			out = append(out, map[string]any{"id": id, "baseVersion": base, "currentVersion": cur, "bytes": size, "createdAt": created, "resolved": res != ""})
		}
		writeJSON(w, out)
	})))
	mux.Handle("GET /api/v1/conflicts/{id}", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		if ids.Validate("cfl", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var digest string
		var size int64
		if e := db.QueryRow(`SELECT c.blob_digest,c.ciphertext_bytes FROM conflicts c JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? WHERE c.id=? AND m.revoked_at=''`, uid, r.PathValue("id")).Scan(&digest, &size); e != nil {
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
	mux.Handle("POST /api/v1/conflicts/{id}/resolve", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		if ids.Validate("cfl", r.PathValue("id")) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var n int
		if db.QueryRow(`SELECT COUNT(*) FROM conflicts c JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? WHERE c.id=? AND m.revoked_at=''`, s.UserID, r.PathValue("id")).Scan(&n) != nil || n == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if _, e := db.Exec(`UPDATE conflicts SET resolved_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), r.PathValue("id")); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("DELETE /api/v1/objects/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		oid := r.PathValue("id")
		var cid, role string
		if ids.Validate("obj", oid) != nil || db.QueryRow(`SELECT o.container_id,m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, oid).Scan(&cid, &role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if e := dbTx(db, func(tx *sql.Tx) error {
			var seq int64
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE objects SET deleted_at=?,change_seq=?,updated_at=? WHERE id=?`, now, seq, now, oid); e != nil {
				return e
			}
			if _, e := tx.Exec(`DELETE FROM attachment_refs WHERE object_id=?`, oid); e != nil {
				return e
			}
			if _, e := tx.Exec(`UPDATE attachments SET deleted_at=? WHERE container_id=? AND deleted_at='' AND NOT EXISTS(SELECT 1 FROM attachment_refs r WHERE r.attachment_id=attachments.id)`, now, cid); e != nil {
				return e
			}
			_, e := tx.Exec(`DELETE FROM object_versions WHERE object_id=?`, oid)
			return e
		}); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/objects/{id}", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		oid := r.PathValue("id")
		if ids.Validate("obj", oid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var cid, digest string
		var version, gen, containerSeq int64
		if e := db.QueryRow(`SELECT o.container_id,v.blob_digest,v.version,v.key_generation,c.change_seq FROM objects o JOIN containers c ON c.id=o.container_id JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? JOIN object_versions v ON v.object_id=o.id AND v.version=CASE WHEN ?='' THEN o.current_version ELSE ? END WHERE o.id=? AND m.revoked_at=''`, uid, r.URL.Query().Get("version"), r.URL.Query().Get("version"), oid).Scan(&cid, &digest, &version, &gen, &containerSeq); e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if d, ok := auth.DeviceFromContext(r); ok {
			var selected int
			if db.QueryRow(`SELECT COUNT(*) FROM device_containers WHERE device_id=? AND container_id=?`, d.ID, cid).Scan(&selected) != nil || selected == 0 {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
		}
		f, size, e := blobs.Open(digest)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("X-Kynotes-Version", strconv.FormatInt(version, 10))
		w.Header().Set("X-Kynotes-Key-Generation", strconv.FormatInt(gen, 10))
		w.Header().Set("X-Kynotes-Digest", digest)
		w.Header().Set("X-Kynotes-Change-Seq", strconv.FormatInt(containerSeq, 10))
		_, _ = io.Copy(w, f)
	})))
	mux.Handle("PUT /api/v1/objects/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		oid := r.PathValue("id")
		if ids.Validate("obj", oid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var cid, role string
		var current int64
		if e := db.QueryRow(`SELECT o.container_id,o.current_version,m.role FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? WHERE o.id=? AND m.revoked_at=''`, s.UserID, oid).Scan(&cid, &current, &role); e != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		var generation int64
		_ = db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation)
		requested, _ := strconv.ParseInt(r.Header.Get("X-Kynotes-Key-Generation"), 10, 64)
		if requested != generation {
			WriteError(w, r, 409, "already_exists", "key rotation incomplete")
			return
		}
		routing := []byte{}
		if encoded := r.Header.Get("X-Kynotes-Routing-Ciphertext"); encoded != "" {
			var decodeErr error
			routing, decodeErr = base64.StdEncoding.DecodeString(encoded)
			if decodeErr != nil || len(routing) > 1024 {
				WriteError(w, r, 400, "invalid_request", "invalid request")
				return
			}
		}
		var missing int
		_ = db.QueryRow(`SELECT COUNT(*) FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' WHERE d.revoked_at='' AND NOT EXISTS(SELECT 1 FROM key_envelopes e WHERE e.container_id=? AND e.device_id=d.id AND e.key_generation=?)`, cid, cid, generation).Scan(&missing)
		if missing > 0 {
			WriteError(w, r, 409, "already_exists", "key rotation incomplete")
			return
		}
		idemKey := r.Header.Get("Idempotency-Key")
		idemHash := ""
		if idemKey != "" {
			sum := sha256.Sum256([]byte(s.UserID + "\x00" + "PUT /api/v1/objects/{id}" + "\x00" + idemKey))
			idemHash = hex.EncodeToString(sum[:])
			var oldStatus int
			var resource string
			if e := db.QueryRow(`SELECT status_code,response_id FROM idempotency_keys WHERE key=?`, idemHash).Scan(&oldStatus, &resource); e == nil {
				if oldStatus == 409 {
					w.WriteHeader(409)
					writeJSON(w, map[string]any{"error": map[string]any{"code": "version_conflict", "message": "base version is stale", "requestId": RequestID(r)}, "conflictId": resource})
					return
				}
				var v int64
				_ = db.QueryRow(`SELECT current_version FROM objects WHERE id=?`, oid).Scan(&v)
				writeJSON(w, map[string]any{"version": v, "resourceId": resource, "commitReceipt": currentCommitReceipt(db, oid, v)})
				return
			}
		}
		base, e := strconv.ParseInt(r.Header.Get("X-Kynotes-Base-Version"), 10, 64)
		if e != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if max > 0 && r.ContentLength > max {
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		tmp, e := blobs.NewTemp(oid + "-" + strconv.FormatInt(time.Now().UnixNano(), 10))
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		body := io.Reader(r.Body)
		if max > 0 {
			body = io.LimitReader(r.Body, max+1)
		}
		if _, e = io.Copy(tmp, body); e != nil {
			_ = tmp.Abort()
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if max > 0 && tmp.Size() > max {
			_ = tmp.Abort()
			WriteError(w, r, 413, "payload_too_large", "payload too large")
			return
		}
		digest, size, e := tmp.Finalize("")
		if e != nil {
			_ = tmp.Abort()
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		tx, e := db.Begin()
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		var live int64
		_ = tx.QueryRow(`SELECT current_version FROM objects WHERE id=?`, oid).Scan(&live)
		var changeSeq int64
		if e = tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1 WHERE id=? RETURNING change_seq`, cid).Scan(&changeSeq); e != nil {
			_ = tx.Rollback()
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if base != live {
			cidID, _ := ids.Mint("cfl")
			_, e = tx.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,?) ON CONFLICT(digest) DO NOTHING`, digest, size, now)
			if e == nil {
				_, e = tx.Exec(`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES(?,?,?) ON CONFLICT DO NOTHING`, digest, cid, now)
			}
			if e == nil {
				_, e = tx.Exec(`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, cidID, oid, cid, base, live, digest, size, generation, changeSeq, now)
			}
			if e == nil && idemHash != "" {
				_, e = tx.Exec(`INSERT INTO idempotency_keys(key,response_id,status_code,created_at) VALUES(?,?,?,?)`, idemHash, cidID, 409, now)
			}
			if e != nil {
				_ = tx.Rollback()
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			_ = tx.Commit()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(409)
			writeJSON(w, map[string]any{"error": map[string]any{"code": "version_conflict", "message": "base version is stale", "requestId": RequestID(r)}, "currentVersion": live, "conflictId": cidID})
			return
		}
		next := live + 1
		_, e = tx.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,?) ON CONFLICT(digest) DO NOTHING`, digest, size, now)
		if e == nil {
			_, e = tx.Exec(`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES(?,?,?) ON CONFLICT DO NOTHING`, digest, cid, now)
		}
		if e == nil {
			_, e = tx.Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,base_version,change_seq,created_at) VALUES(?,?,?,?,?,?,?,?)`, oid, next, digest, size, generation, base, changeSeq, now)
		}
		if e == nil {
			_, e = tx.Exec(`UPDATE objects SET current_version=?,change_seq=?,routing_ciphertext=?,updated_at=? WHERE id=?`, next, changeSeq, routing, now, oid)
		}
		if e == nil && idemHash != "" {
			_, e = tx.Exec(`INSERT INTO idempotency_keys(key,response_id,status_code,created_at) VALUES(?,?,?,?)`, idemHash, oid, 200, now)
		}
		if e != nil {
			_ = tx.Rollback()
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if e = tx.Commit(); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"version": next, "digest": digest, "bytes": size, "commitReceipt": commitReceipt(oid, digest, next, size, generation, base, changeSeq)})
	})))
}
