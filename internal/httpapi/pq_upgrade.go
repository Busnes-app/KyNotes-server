package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/keyprotocol"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Upgrade retains the device row and old decryption key, preserving every historical
// envelope. New generations wait for all approved members to upgrade and re-trust.
func pqUpgradeRoutes(mux RouteMux, db *sql.DB) {
	mux.Handle("POST /api/v1/me/identity/pq-upgrade", auth.RequireUserActionStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct{ DeviceID, PublicKey, WrapAlg, WrappedPrivateKey, RecoveryKey string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
		wrapped, we := base64.StdEncoding.DecodeString(in.WrappedPrivateKey)
		recovery, re := base64.StdEncoding.DecodeString(in.RecoveryKey)
		if err != nil || we != nil || re != nil || len(pub) != keyprotocol.PQPublicBytes || keyprotocol.ValidatePublicIdentity(pub) != nil || len(recovery) != keyprotocol.PQRecoveryBytes || !(in.WrapAlg == identityWrapAlg && len(wrapped) == keyprotocol.PQWrappedIdentityBytes || in.WrapAlg == deviceOnlyWrapAlg && len(wrapped) == 0) || s.SSOIssuer != "" && in.WrapAlg != deviceOnlyWrapAlg {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		sum := sha256.Sum256(pub)
		fp := hex.EncodeToString(sum[:])
		var recoveryID string
		err = dbTx(db, func(tx *sql.Tx) error {
			now := time.Now().UTC()
			stamp := now.Format(time.RFC3339)
			if err := auth.RecheckUserActionTx(tx, s, now); err != nil {
				return err
			}
			var device, oldPublic, oldAlg, oldRecovery string
			var oldWrapped, oldRecoveryBytes []byte
			var linked bool
			err := tx.QueryRow(`SELECT i.device_id,d.public_key,i.wrap_alg,i.wrapped_private_key,i.recovery_id,i.recovery_wrapped_key,u.sso_subject<>'' FROM user_identities i JOIN devices d ON d.id=i.device_id JOIN users u ON u.id=i.user_id WHERE i.user_id=?`, s.UserID).Scan(&device, &oldPublic, &oldAlg, &oldWrapped, &oldRecovery, &oldRecoveryBytes, &linked)
			if errors.Is(err, sql.ErrNoRows) {
				return errIdentityMissing
			}
			if err != nil {
				return err
			}
			if device != in.DeviceID {
				return errRecoveryMoved
			}
			if linked && in.WrapAlg != deviceOnlyWrapAlg || !linked && s.SSOIssuer == "" && in.WrapAlg != identityWrapAlg {
				return errEnvelopeInvalid
			}
			old, err := base64.StdEncoding.DecodeString(oldPublic)
			if err != nil {
				return err
			}
			if bytes.Equal(old, pub) && oldAlg == in.WrapAlg && bytes.Equal(oldWrapped, wrapped) && bytes.Equal(oldRecoveryBytes, recovery) {
				recoveryID = oldRecovery
				return nil
			}
			if len(old) != 32 || !bytes.Equal(old, pub[1:33]) {
				return errRecoveryMoved
			}
			recoveryID, err = ids.Mint("rcv")
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE devices SET public_key=?,fingerprint=? WHERE id=?`, base64.StdEncoding.EncodeToString(pub), fp, device); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE user_identities SET wrapped_private_key=?,wrap_alg=?,recovery_id=?,recovery_alg=?,recovery_wrapped_key=?,recovery_updated_at=?,updated_at=? WHERE user_id=?`, wrapped, in.WrapAlg, recoveryID, recoveryWrapAlg, recovery, stamp, stamp, s.UserID); err != nil {
				return err
			}
			// End in-flight classical links and force old browsers to obtain the upgraded copy.
			if _, err := tx.Exec(`DELETE FROM link_requests WHERE user_id=?`, s.UserID); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at=''`, stamp, s.UserID, s.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE devices SET revoked_at=? WHERE user_id=? AND platform<>'identity' AND revoked_at=''`, stamp, s.UserID); err != nil {
				return err
			}
			retired, err := retireKeysTx(tx, s.UserID, stamp)
			if err != nil {
				return err
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "identity.pq_upgrade", "", device, "success", fmt.Sprintf("containers_retired=%d", retired), RequestID(r))
		})
		if errors.Is(err, errEnvelopeInvalid) {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if writeIdentityError(w, r, err) {
			return
		}
		writeJSON(w, map[string]string{"deviceId": in.DeviceID, "fingerprint": fp, "recoveryId": recoveryID})
	})))
}
