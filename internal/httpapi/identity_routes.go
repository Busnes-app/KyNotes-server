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

var (
	errIdentityExists  = errors.New("identity exists")
	errIdentityRewrap  = errors.New("identity rewrap mismatch")
	errPasswordChanged = errors.New("password changed concurrently")
	// errPasswordChangeRequired: someone other than the user knows the password.
	errPasswordChangeRequired = errors.New("password change required")
)

func decodeWrappedIdentity(value string) ([]byte, bool) {
	wrapped, err := base64.StdEncoding.DecodeString(value)
	return wrapped, err == nil && len(wrapped) == wrappedIdentityBytes
}

// loadIdentity returns nil when the user has none. The wrapped private key is an
// offline password-guessing target, so only responses that just verified the
// password (local login and step-up) may ask for it; a session cookie never can.
func loadIdentity(db interface {
	QueryRow(string, ...any) *sql.Row
}, userID string, withWrapped bool) (map[string]string, error) {
	var deviceID, publicKey, fingerprint, alg, created, updated string
	var wrapped []byte
	err := db.QueryRow(`SELECT i.device_id,d.public_key,d.fingerprint,i.wrap_alg,i.wrapped_private_key,i.created_at,i.updated_at FROM user_identities i JOIN devices d ON d.id=i.device_id WHERE i.user_id=?`, userID).Scan(&deviceID, &publicKey, &fingerprint, &alg, &wrapped, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{"deviceId": deviceID, "publicKey": publicKey, "fingerprint": fingerprint, "createdAt": created, "updatedAt": updated}
	if withWrapped {
		out["wrapAlg"] = alg
		out["wrappedPrivateKey"] = base64.StdEncoding.EncodeToString(wrapped)
	}
	return out, nil
}

func IdentityRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /api/v1/me/identity", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		identity, err := loadIdentity(db, s.UserID, false)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if identity == nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, identity)
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
			// Recovery or a password change may have committed since the middleware ran.
			if err := auth.RecheckUserStepUpTx(tx, s, time.Now().UTC()); err != nil {
				return err
			}
			var taken, adminKnown int
			if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM devices WHERE user_id=? AND (platform='identity' OR fingerprint=?)),(SELECT password_admin_known FROM users WHERE id=?)`, s.UserID, fingerprint, s.UserID).Scan(&taken, &adminKnown); err != nil {
				return err
			}
			if taken > 0 {
				return errIdentityExists
			}
			if adminKnown != 0 {
				return errPasswordChangeRequired
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
		if errors.Is(err, auth.ErrSessionInvalid) {
			auth.WriteAuthError(w, "unauthenticated", "authentication required")
			return
		}
		if errors.Is(err, auth.ErrStepUpInvalid) {
			auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		if errors.Is(err, errPasswordChangeRequired) {
			WriteError(w, r, 409, "password_change_required", "change the password an administrator set before creating an identity")
			return
		}
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

// deleteIdentityTx deletes the user's identity (cascading to its wrapped key and
// envelopes) when its wrapping password is gone, and audits the deletion.
func deleteIdentityTx(tx *sql.Tx, userID, actor, requestID string) error {
	var deviceID string
	err := tx.QueryRow(`DELETE FROM devices WHERE user_id=? AND platform='identity' RETURNING id`, userID).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, actor, "identity.delete", "", deviceID, "success", "", requestID)
}

// afterPasswordVerified lets tests commit a concurrent change between a password
// verification and the transaction that acts on it. Always nil in production.
var afterPasswordVerified func()
