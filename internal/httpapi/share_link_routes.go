package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

var errQuota = errors.New("quota exceeded")

// MaxShareLinkLifetime caps a sealed share link's expiry; GC deletes a link once it expires.
const MaxShareLinkLifetime = 30 * 24 * time.Hour

func ShareLinkRoutes(mux RouteMux, db *sql.DB, blobs *blobstore.Store, limits config.Limits) {
	mux.Handle("POST /api/v1/share-links", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			Ciphertext string `json:"ciphertext"`
			ExpiresAt  string `json:"expiresAt"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		expires, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !expires.After(time.Now().UTC()) || expires.After(time.Now().UTC().Add(MaxShareLinkLifetime)) {
			WriteError(w, r, 400, "invalid_request", "invalid expiry: a share link lasts at most 30 days")
			return
		}
		sealed, err := base64.RawURLEncoding.DecodeString(in.Ciphertext)
		if err != nil || len(sealed) < 16 || len(sealed) > 12<<20 {
			WriteError(w, r, 400, "invalid_request", "invalid ciphertext")
			return
		}
		id, _ := ids.Mint("shl")
		var tokenBytes [32]byte
		if _, err = rand.Read(tokenBytes[:]); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
		sum := sha256.Sum256([]byte(token))
		now := time.Now().UTC().Format(time.RFC3339)
		err = dbTx(db, func(tx *sql.Tx) error {
			var quota int64
			if e := tx.QueryRow(`SELECT quota_bytes FROM users WHERE id=?`, s.UserID).Scan(&quota); e != nil {
				return e
			}
			if over, e := userQuotaExceeded(tx, limits, s.UserID, quota, "", int64(len(sealed))); e != nil || over {
				if e == nil {
					e = errQuota
				}
				return e
			}
			if _, e := tx.Exec(`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES(?,?,?,?,?,?)`, id, hex.EncodeToString(sum[:]), sealed, expires.UTC().Format(time.RFC3339), now, s.UserID); e != nil {
				return e
			}
			if e := storage.RecordAuditOutcomeTx(tx, s.UserID, "share_link.create", "", id, "success", "", RequestID(r)); e != nil {
				return e
			}
			return checkDatabaseBudget(tx)
		})
		if writeStorageFull(w, r, err) {
			return
		}
		if errors.Is(err, errQuota) {
			WriteError(w, r, 413, "quota_exceeded", "quota exceeded")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"id": id, "token": token, "expiresAt": expires.UTC().Format(time.RFC3339)})
	})))

	// The caller's own live sealed links, newest first, so they can revoke one they regret.
	mux.Handle("GET /api/v1/share-links", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		rows, err := db.Query(`SELECT id,created_at,expires_at,length(ciphertext) FROM sealed_share_links WHERE owner_user_id=? AND revoked_at='' AND expires_at>? ORDER BY created_at DESC,id`, s.UserID, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		type link struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
			ExpiresAt string `json:"expiresAt"`
			Bytes     int64  `json:"bytes"`
		}
		out := []link{}
		for rows.Next() {
			var l link
			if rows.Scan(&l.ID, &l.CreatedAt, &l.ExpiresAt, &l.Bytes) == nil {
				out = append(out, l)
			}
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})))

	mux.Handle("DELETE /api/v1/share-links/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		if ids.Validate("shl", id) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		err := dbTx(db, func(tx *sql.Tx) error {
			res, e := tx.Exec(`UPDATE sealed_share_links SET revoked_at=? WHERE id=? AND owner_user_id=? AND revoked_at=''`, time.Now().UTC().Format(time.RFC3339), id, s.UserID)
			if e != nil {
				return e
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return sql.ErrNoRows
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "share_link.revoke", "", id, "success", "", RequestID(r))
		})
		if errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	mux.Handle("POST /api/v1/objects/{id}/share-links", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			Version   int64  `json:"version"`
			ExpiresAt string `json:"expiresAt"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		expires, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !expires.After(time.Now().UTC()) {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var objectID, digest string
		var version, generation, baseVersion, changeSeq, size int64
		if in.Version < 0 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		versionSelector := in.Version
		if versionSelector == 0 {
			if err = db.QueryRow(`SELECT o.id,o.current_version FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? AND m.revoked_at='' WHERE o.id=?`, s.UserID, r.PathValue("id")).Scan(&objectID, &versionSelector); err != nil {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
		} else {
			objectID = r.PathValue("id")
		}
		if ids.Validate("obj", objectID) != nil || db.QueryRow(`SELECT o.id,v.blob_digest,v.version,v.key_generation,v.base_version,v.change_seq,v.ciphertext_bytes FROM objects o JOIN memberships m ON m.container_id=o.container_id AND m.user_id=? AND m.revoked_at='' JOIN object_versions v ON v.object_id=o.id AND v.version=? WHERE o.id=?`, s.UserID, versionSelector, objectID).Scan(&objectID, &digest, &version, &generation, &baseVersion, &changeSeq, &size) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var tokenBytes [32]byte
		if _, err = rand.Read(tokenBytes[:]); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
		sum := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(sum[:])
		id, err := ids.Mint("shl")
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		created := time.Now().UTC().Format(time.RFC3339)
		err = dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`INSERT INTO share_links(id,token_hash,object_id,object_version,expires_at,created_at) VALUES(?,?,?,?,?,?)`, id, tokenHash, objectID, version, expires.UTC().Format(time.RFC3339), created); e != nil {
				return e
			}
			return checkDatabaseBudget(tx)
		})
		if writeStorageFull(w, r, err) {
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"id": id, "token": token, "objectId": objectID, "version": version, "expiresAt": expires.UTC().Format(time.RFC3339), "commitReceipt": commitReceipt(objectID, digest, version, size, generation, baseVersion, changeSeq)})
	})))

	mux.HandleFunc("GET /api/v1/share-links/{token}", func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if len(token) != 43 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		sum := sha256.Sum256([]byte(token))
		var sealedExpires string
		var sealed []byte
		if err := db.QueryRow(`SELECT ciphertext,expires_at FROM sealed_share_links WHERE token_hash=? AND revoked_at=''`, hex.EncodeToString(sum[:])).Scan(&sealed, &sealedExpires); err == nil {
			expiresAt, parseErr := time.Parse(time.RFC3339, sealedExpires)
			if parseErr != nil || !expiresAt.After(time.Now().UTC()) {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(sealed)))
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(sealed)
			return
		}
		var objectID, digest, expires string
		var version, generation, baseVersion, changeSeq, size int64
		if db.QueryRow(`SELECT l.object_id,l.object_version,l.expires_at,COALESCE(v.blob_digest,''),COALESCE(v.key_generation,0),COALESCE(v.base_version,0),COALESCE(v.change_seq,0),COALESCE(v.ciphertext_bytes,0) FROM share_links l LEFT JOIN objects o ON o.id=l.object_id LEFT JOIN object_versions v ON v.object_id=l.object_id AND v.version=l.object_version WHERE l.token_hash=? AND l.revoked_at=''`, hex.EncodeToString(sum[:])).Scan(&objectID, &version, &expires, &digest, &generation, &baseVersion, &changeSeq, &size) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, expires)
		if err != nil || !expiresAt.After(time.Now().UTC()) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		var body io.Reader
		if len(sealed) > 0 {
			body = bytes.NewReader(sealed)
			size = int64(len(sealed))
		} else {
			f, actualSize, openErr := blobs.Open(digest)
			if openErr != nil || actualSize != size {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
			defer f.Close()
			body = f
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Kynotes-Object", objectID)
		w.Header().Set("X-Kynotes-Version", strconv.FormatInt(version, 10))
		w.Header().Set("X-Kynotes-Key-Generation", strconv.FormatInt(generation, 10))
		w.Header().Set("X-Kynotes-Digest", digest)
		w.Header().Set("X-Kynotes-Change-Seq", strconv.FormatInt(changeSeq, 10))
		if digest != "" {
			w.Header().Set("X-Kynotes-Commit-Receipt", commitReceipt(objectID, digest, version, size, generation, baseVersion, changeSeq))
		}
		_, _ = io.Copy(w, body)
	})
}
