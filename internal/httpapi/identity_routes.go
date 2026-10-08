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
	"fmt"
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

const deviceOnlyWrapAlg = "none" // created by an SSO session, or stripped by a reset: no password copy

// The recovery-code copy: salt(16) | nonce(12) | AES-256-GCM(KEK, privateKey(32)) | tag(16), KEK =
// PBKDF2-SHA256(code secret, salt, 600000). The server checks only the label and length.
const (
	recoveryWrapAlg   = "pbkdf2-sha256-600000/aes-256-gcm"
	recoveryWrapBytes = 76
)

func decodeRecoveryCopy(alg, value string) ([]byte, bool) {
	wrapped, err := base64.StdEncoding.DecodeString(value)
	return wrapped, alg == recoveryWrapAlg && err == nil && len(wrapped) == recoveryWrapBytes
}

var (
	errIdentityExists  = errors.New("identity exists")
	errIdentityRewrap  = errors.New("identity rewrap mismatch")
	errPasswordChanged = errors.New("password changed concurrently")
	errIdentityMissing = errors.New("no identity")
	errRecoveryMoved   = errors.New("recovery copy changed")
)

// errResetWrap: a local reset's copy kind does not match the account. linked: a KySignOn-linked
// account sent a password copy; else a password account sent none.
type errResetWrap struct{ linked bool }

func (errResetWrap) Error() string { return "reset wrap does not match the account" }

func decodeWrappedIdentity(value string) ([]byte, bool) {
	wrapped, err := base64.StdEncoding.DecodeString(value)
	return wrapped, err == nil && len(wrapped) == wrappedIdentityBytes
}

// passwordCopyAddableSQL (over user_identities i) is true when the user's own password change may
// re-add a password copy: a reset stripped it. An account with a KySignOn subject never qualifies,
// since its device-only identity may never have had one.
const passwordCopyAddableSQL = `(i.wrap_alg='none' AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=i.user_id AND u.sso_subject<>''))`

// loadIdentity returns nil when the user has none. The wrapped private key is an
// offline password-guessing target, so only responses that just verified the
// password (local login and step-up) may ask for it; a session cookie never can.
func loadIdentity(db interface {
	QueryRow(string, ...any) *sql.Row
}, userID string, withWrapped bool) (map[string]string, error) {
	var deviceID, publicKey, fingerprint, alg, created, updated, recoveryID, recoveryAt string
	var wrapped []byte
	var addable bool
	// The recovery-code copy is never selected here: only the fetch route returns it.
	err := db.QueryRow(`SELECT i.device_id,d.public_key,d.fingerprint,i.wrap_alg,i.wrapped_private_key,i.created_at,i.updated_at,i.recovery_id,i.recovery_updated_at,`+passwordCopyAddableSQL+` FROM user_identities i JOIN devices d ON d.id=i.device_id WHERE i.user_id=?`, userID).Scan(&deviceID, &publicKey, &fingerprint, &alg, &wrapped, &created, &updated, &recoveryID, &recoveryAt, &addable)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{"deviceId": deviceID, "publicKey": publicKey, "fingerprint": fingerprint, "wrapAlg": alg, "createdAt": created, "updatedAt": updated, "recoveryId": recoveryID, "recoverySetAt": recoveryAt}
	if addable {
		out["passwordCopy"] = "addable"
	}
	if withWrapped {
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
	mux.Handle("PUT /api/v1/me/identity", auth.RequireUserActionStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			PublicKey         string `json:"publicKey"`
			WrapAlg           string `json:"wrapAlg"`
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
			// Replace is the self-service reset: the old identity and every key it held go in this commit.
			Replace bool `json:"replace"`
			// The identity the browser saw listed ("" for none); a different current one is refused.
			ExpectedDeviceID *string `json:"expectedDeviceId"`
			Recovery         *struct {
				WrapAlg    string `json:"wrapAlg"`
				WrappedKey string `json:"wrappedKey"`
			} `json:"recovery"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		sso := s.SSOIssuer != ""
		pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
		var wrapped, recovery []byte
		ok := err == nil && len(pub) == 32
		switch {
		case !sso && in.WrapAlg == identityWrapAlg:
			var good bool
			wrapped, good = decodeWrappedIdentity(in.WrappedPrivateKey)
			ok = ok && good
		case (sso || in.Replace) && in.WrapAlg == deviceOnlyWrapAlg && in.WrappedPrivateKey == "":
			// Nothing an SSO session proves could wrap a key: the identity lives only in browsers. A local
			// session sends this only for a KySignOn-linked account's reset (checked in the transaction).
			wrapped = []byte{}
		default:
			ok = false
		}
		recoveryID, recoveryAlg, recoveryAt := "", "", ""
		if in.Replace {
			// A reset carries its recovery-code copy, so the new identity never exists without a way back.
			// Password accounts keep their password copy (spec §8); KySignOn-linked accounts never get one.
			good := false
			if in.Recovery != nil {
				recovery, good = decodeRecoveryCopy(in.Recovery.WrapAlg, in.Recovery.WrappedKey)
				recoveryAlg, recoveryAt = recoveryWrapAlg, time.Now().UTC().Format(time.RFC3339)
			}
			ok = ok && good && in.ExpectedDeviceID != nil
		} else {
			// A copy for an existing identity goes through PUT /me/identity/recovery.
			ok = ok && in.Recovery == nil && in.ExpectedDeviceID == nil
			recovery = []byte{}
		}
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if in.Replace {
			if recoveryID, err = ids.Mint("rcv"); err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
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
		resetReason := ""
		err = dbTx(db, func(tx *sql.Tx) error {
			// Recovery or a password change may have committed since the middleware ran.
			if err := auth.RecheckUserActionTx(tx, s, time.Now().UTC()); err != nil {
				return err
			}
			if in.Replace && !sso {
				var linked bool
				if err := tx.QueryRow(`SELECT sso_subject<>'' FROM users WHERE id=?`, s.UserID).Scan(&linked); err != nil {
					return err
				}
				if linked != (in.WrapAlg == deviceOnlyWrapAlg) {
					return errResetWrap{linked}
				}
			}
			if in.Replace {
				// Compare-and-swap: only the identity this browser saw listed is replaced.
				var current string
				if err := tx.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, s.UserID).Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if current != *in.ExpectedDeviceID {
					return errRecoveryMoved
				}
				// Whoever held the old identity keeps nothing: other sessions and device credentials end here,
				// as on a password change.
				sessions, err := tx.Exec(`UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at=''`, now, s.UserID, s.ID)
				if err != nil {
					return err
				}
				devices, err := tx.Exec(`UPDATE devices SET revoked_at=? WHERE user_id=? AND platform<>'identity' AND revoked_at=''`, now, s.UserID)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(`DELETE FROM key_envelopes WHERE device_id IN (SELECT id FROM devices WHERE user_id=? AND platform<>'identity')`, s.UserID); err != nil {
					return err
				}
				ns, _ := sessions.RowsAffected()
				nd, _ := devices.RowsAffected()
				revoked := fmt.Sprintf("sessions_revoked=%d,devices_revoked=%d", ns, nd)
				oldFingerprint, err := deleteIdentityTx(tx, s.UserID, s.UserID, RequestID(r), revoked)
				if err != nil {
					return err
				}
				// The old key may sit in a stolen browser: resetting to it cuts nothing off.
				if oldFingerprint == fingerprint {
					return errIdentityExists
				}
				if oldFingerprint == "" {
					resetReason = "," + revoked // no identity.reset row carries the counts
				}
			}
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
			if _, err := tx.Exec(`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at,recovery_id,recovery_alg,recovery_wrapped_key,recovery_updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, s.UserID, deviceID, wrapped, in.WrapAlg, now, now, recoveryID, recoveryAlg, recovery, recoveryAt); err != nil {
				return err
			}
			// Which proof created it: the password, or the KySignOn grant (decision 4's trace). No key material.
			proof := "proof=password"
			if sso {
				proof = "proof=sso:" + r.Header.Get("X-Kynotes-Step-Up")
			}
			if in.Replace {
				proof += ",reset" + resetReason
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.create", "", deviceID, "success", "wrap="+in.WrapAlg+","+proof, RequestID(r))
		})
		if errors.Is(err, auth.ErrSessionInvalid) {
			auth.WriteAuthError(w, "unauthenticated", "authentication required")
			return
		}
		if errors.Is(err, auth.ErrStepUpInvalid) {
			auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
			return
		}
		if errors.Is(err, auth.ErrPasswordAdminKnown) {
			WriteError(w, r, 409, "password_change_required", "change the password an administrator set before creating an identity")
			return
		}
		if errors.Is(err, errRecoveryMoved) {
			WriteError(w, r, 409, "already_exists", "your encryption key changed meanwhile; reload and try again")
			return
		}
		if errors.Is(err, errIdentityExists) {
			WriteError(w, r, 409, "identity_exists", "an identity already exists for this account")
			return
		}
		var wrapErr errResetWrap
		if errors.As(err, &wrapErr) {
			if wrapErr.linked {
				WriteError(w, r, 409, "device_only_required", "an account linked to KySignOn keeps no password copy of its key")
			} else {
				WriteError(w, r, 400, "invalid_request", "invalid request")
			}
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]string{"deviceId": deviceID, "fingerprint": fingerprint})
	})))
	// The recovery-code copy is set and fetched only behind a user-action step-up (a local password
	// re-proof, or KySignOn for this exact request); the server never sees the code.
	mux.Handle("PUT /api/v1/me/identity/recovery", auth.RequireUserActionStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			DeviceID           string `json:"deviceId"`
			ExpectedRecoveryID string `json:"expectedRecoveryId"`
			WrapAlg            string `json:"wrapAlg"`
			WrappedKey         string `json:"wrappedKey"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || ids.Validate("dev", in.DeviceID) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		wrapped, ok := decodeRecoveryCopy(in.WrapAlg, in.WrappedKey)
		if !ok {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		next, err := ids.Mint("rcv")
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		err = dbTx(db, func(tx *sql.Tx) error {
			if err := auth.RecheckUserActionTx(tx, s, time.Now().UTC()); err != nil {
				return err
			}
			var device, current string
			var stored []byte
			err := tx.QueryRow(`SELECT device_id,recovery_id,recovery_wrapped_key FROM user_identities WHERE user_id=?`, s.UserID).Scan(&device, &current, &stored)
			if errors.Is(err, sql.ErrNoRows) {
				return errIdentityMissing
			}
			if err != nil {
				return err
			}
			// A re-send after a lost response: every seal has a fresh salt and nonce, so identical bytes are this upload.
			if device == in.DeviceID && current != "" && bytes.Equal(stored, wrapped) {
				next = current
				return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.recovery.set", "", device, "success", "replayed", RequestID(r))
			}
			// Compare-and-swap: only the copy this browser last saw, of the identity it holds, is replaced.
			if device != in.DeviceID || current != in.ExpectedRecoveryID {
				return errRecoveryMoved
			}
			now := time.Now().UTC().Format(time.RFC3339)
			res, err := tx.Exec(`UPDATE user_identities SET recovery_id=?,recovery_alg=?,recovery_wrapped_key=?,recovery_updated_at=?,updated_at=? WHERE user_id=? AND recovery_id=?`, next, in.WrapAlg, wrapped, now, now, s.UserID, current)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return errRecoveryMoved
			}
			reason := "created"
			if current != "" {
				reason = "replaced"
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.recovery.set", "", device, "success", reason, RequestID(r))
		})
		if writeIdentityError(w, r, err) {
			return
		}
		writeJSON(w, map[string]string{"recoveryId": next})
	})))
	// POST and CSRF like link collect (SecurityHeaders sends no-store): a cross-site navigation can neither read nor spend it.
	// No identity and no copy are the same audited 404.
	mux.Handle("POST /api/v1/me/identity/recovery/fetch", auth.RequireUserActionStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var out map[string]string
		err := dbTx(db, func(tx *sql.Tx) error {
			if err := auth.RecheckUserActionTx(tx, s, time.Now().UTC()); err != nil {
				return err
			}
			var device, public, id, alg string
			var wrapped []byte
			err := tx.QueryRow(`SELECT i.device_id,d.public_key,i.recovery_id,i.recovery_alg,i.recovery_wrapped_key FROM user_identities i JOIN devices d ON d.id=i.device_id WHERE i.user_id=? AND i.recovery_id<>''`, s.UserID).Scan(&device, &public, &id, &alg, &wrapped)
			if errors.Is(err, sql.ErrNoRows) {
				return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.recovery.fetch", "", "", "denied", "none", RequestID(r))
			}
			if err != nil {
				return err
			}
			out = map[string]string{"deviceId": device, "publicKey": public, "recoveryId": id, "wrapAlg": alg, "wrappedKey": base64.StdEncoding.EncodeToString(wrapped)}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.recovery.fetch", "", device, "success", "recovery="+id, RequestID(r))
		})
		if err == nil && out == nil {
			err = errIdentityMissing
		}
		if writeIdentityError(w, r, err) {
			return
		}
		writeJSON(w, out)
	})))
}

// writeIdentityError answers an identity route's transaction error; false when err is nil.
func writeIdentityError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, auth.ErrSessionInvalid):
		auth.WriteAuthError(w, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrStepUpInvalid):
		auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
	case errors.Is(err, auth.ErrPasswordAdminKnown):
		WriteError(w, r, 409, "password_change_required", "change the password an administrator set first")
	case errors.Is(err, errIdentityMissing):
		WriteError(w, r, 404, "not_found", "not found")
	case errors.Is(err, errRecoveryMoved):
		WriteError(w, r, 409, "already_exists", "the recovery code changed meanwhile; reload and try again")
	default:
		WriteError(w, r, 500, "internal", "internal server error")
	}
	return true
}

// deleteIdentityTx is the self-service reset: it deletes the user's identity, which cascades to its
// envelopes and both copies, and its link requests, and audits identity.reset with reason. It returns
// the deleted identity's fingerprint, "" when there was none.
func deleteIdentityTx(tx *sql.Tx, userID, actor, requestID, reason string) (string, error) {
	if _, err := tx.Exec(`DELETE FROM link_requests WHERE user_id=?`, userID); err != nil {
		return "", err
	}
	var deviceID, fingerprint string
	err := tx.QueryRow(`DELETE FROM devices WHERE user_id=? AND platform='identity' RETURNING id,fingerprint`, userID).Scan(&deviceID, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return fingerprint, storage.RecordAuditOutcomeTx(tx, actor, "identity.reset", "", deviceID, "success", reason, requestID)
}

// stripPasswordWrapTx serves account recovery and an administrator password reset: whoever sets the
// new password cannot re-wrap the identity, so only its password copy goes. The identity, its envelopes
// and its recovery-code copy stay; another browser or the recovery code still holds it. Link requests
// go too: they belong to sessions the reset revokes.
func stripPasswordWrapTx(tx *sql.Tx, userID, actor, requestID string) error {
	if _, err := tx.Exec(`DELETE FROM link_requests WHERE user_id=?`, userID); err != nil {
		return err
	}
	var deviceID string
	err := tx.QueryRow(`UPDATE user_identities SET wrap_alg=?,wrapped_private_key=X'',updated_at=? WHERE user_id=? AND wrap_alg=? RETURNING device_id`, deviceOnlyWrapAlg, time.Now().UTC().Format(time.RFC3339), userID, identityWrapAlg).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, actor, "identity.password_wrap.delete", "", deviceID, "success", "", requestID)
}

// afterPasswordVerified lets tests commit a concurrent change between a password
// verification and the transaction that acts on it. Always nil in production.
var afterPasswordVerified func()
