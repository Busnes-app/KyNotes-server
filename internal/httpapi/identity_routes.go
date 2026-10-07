package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// The wrapped identity is nonce(12) | AES-256-GCM(userKEK, privateKey(32)) | tag(16).
// The server stores it opaque; only its length and algorithm label are checked.
const (
	identityWrapAlg      = "aes-256-gcm"
	wrappedIdentityBytes = 60
)

var errIdentityExists = errors.New("identity exists")

func decodeWrappedIdentity(value string) ([]byte, bool) {
	wrapped, err := base64.StdEncoding.DecodeString(value)
	return wrapped, err == nil && len(wrapped) == wrappedIdentityBytes
}

func IdentityRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /api/v1/me/identity", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		var deviceID, publicKey, fingerprint, alg, created, updated string
		var wrapped []byte
		err := db.QueryRow(`SELECT i.device_id,d.public_key,d.fingerprint,i.wrap_alg,i.wrapped_private_key,i.created_at,i.updated_at FROM user_identities i JOIN devices d ON d.id=i.device_id WHERE i.user_id=?`, s.UserID).Scan(&deviceID, &publicKey, &fingerprint, &alg, &wrapped, &created, &updated)
		if errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"deviceId": deviceID, "publicKey": publicKey, "fingerprint": fingerprint, "wrapAlg": alg, "wrappedPrivateKey": base64.StdEncoding.EncodeToString(wrapped), "createdAt": created, "updatedAt": updated})
	})))
	mux.Handle("PUT /api/v1/me/identity", auth.RequireUserStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			PublicKey         string `json:"publicKey"`
			WrapAlg           string `json:"wrapAlg"`
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.WrapAlg != identityWrapAlg {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
		wrapped, ok := decodeWrappedIdentity(in.WrappedPrivateKey)
		if err != nil || len(pub) != 32 || !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		fp := sha256.Sum256(pub)
		fingerprint := hex.EncodeToString(fp[:])
		deviceID, err := ids.Mint("dev")
		unusable := make([]byte, 32)
		if err == nil {
			_, err = rand.Read(unusable)
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		err = dbTx(db, func(tx *sql.Tx) error {
			var taken int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND (platform='identity' OR fingerprint=?)`, s.UserID, fingerprint).Scan(&taken); err != nil {
				return err
			}
			if taken > 0 {
				return errIdentityExists
			}
			// secret_hash never carries the "sha256:" prefix device auth compares against.
			if _, err := tx.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,?,?,?,'identity',?)`, deviceID, s.UserID, base64.StdEncoding.EncodeToString(pub), fingerprint, "identity:"+hex.EncodeToString(unusable), now); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES(?,?,?,?,?,?)`, s.UserID, deviceID, wrapped, identityWrapAlg, now, now); err != nil {
				return err
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.create", "", deviceID, "success", "", RequestID(r))
		})
		if errors.Is(err, errIdentityExists) {
			WriteError(w, r, 409, "identity_exists", "an identity already exists for this account")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]string{"deviceId": deviceID, "fingerprint": fingerprint})
	})))
}
