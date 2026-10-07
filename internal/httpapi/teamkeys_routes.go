package httpapi

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
)

const envelopeAlg = "x25519-hkdf-sha256-chacha20poly1305"

var (
	errNotMember             = errors.New("not a member")
	errInsufficientRole      = errors.New("insufficient role")
	errEnvelopeInvalid       = errors.New("invalid envelope")
	errEnvelopeExists        = errors.New("envelope exists")
	errGenerationMoved       = errors.New("key generation changed")
	errKeyRotationIncomplete = errors.New("key rotation incomplete")
)

type envelopeIn struct {
	DeviceID      string `json:"deviceId"`
	KeyGeneration int64  `json:"keyGeneration"`
	Alg           string `json:"alg"`
	Envelope      string `json:"envelope"`
}

func (v envelopeIn) bytes() ([]byte, bool) {
	env, err := base64.StdEncoding.DecodeString(v.Envelope)
	return env, err == nil && v.Alg == envelopeAlg && len(env) > 0 && len(env) <= 4096 && ids.Validate("dev", v.DeviceID) == nil
}

// writeTeamKeyError maps team-key and write-gate errors; false when err is nil.
func writeTeamKeyError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, auth.ErrSessionInvalid):
		auth.WriteAuthError(w, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrStepUpInvalid):
		auth.WriteAuthError(w, "step_up_required", "re-enter your password to continue")
	case errors.Is(err, errNotMember), errors.Is(err, sql.ErrNoRows):
		WriteError(w, r, 404, "not_found", "not found")
	case errors.Is(err, errInsufficientRole):
		WriteError(w, r, 403, "forbidden", "insufficient role")
	case errors.Is(err, errEnvelopeInvalid):
		WriteError(w, r, 400, "invalid_request", "invalid request")
	case errors.Is(err, errEnvelopeExists):
		WriteError(w, r, 409, "already_exists", "envelope already exists")
	case errors.Is(err, errGenerationMoved):
		WriteError(w, r, 409, "already_exists", "key generation changed")
	case errors.Is(err, errKeyRotationIncomplete):
		WriteError(w, r, 409, "already_exists", "key rotation incomplete")
	default:
		WriteError(w, r, 500, "internal", "internal server error")
	}
	return true
}

// memberTx returns the caller's role and the container's current generation.
func memberTx(tx *sql.Tx, cid, userID string) (role string, generation int64, err error) {
	err = tx.QueryRow(`SELECT m.role,c.key_generation FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at=''`, cid, userID).Scan(&role, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotMember
	}
	return role, generation, err
}

func isSteward(role string) bool { return role == "owner" || role == "admin" }

// insertEnvelopeTx stores one envelope in cid at generation for caller (holding
// role there). The recipient must be a live device or identity of an active
// member; non-stewards may write only for their own. Insert-only: an existing
// (container, recipient, generation) row is errEnvelopeExists, except the
// caller's own identity, which may be re-wrapped but never first-written by a
// non-steward (a steward or an invitation supplies the first one).
func insertEnvelopeTx(tx *sql.Tx, cid string, generation int64, caller, role string, v envelopeIn, now string) error {
	env, ok := v.bytes()
	if !ok {
		return errEnvelopeInvalid
	}
	if v.KeyGeneration != generation {
		return errGenerationMoved
	}
	var owner, platform string
	err := tx.QueryRow(`SELECT d.user_id,d.platform FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' JOIN users u ON u.id=d.user_id AND u.status='active' WHERE d.id=? AND d.revoked_at=''`, cid, v.DeviceID).Scan(&owner, &platform)
	if errors.Is(err, sql.ErrNoRows) {
		return errEnvelopeInvalid
	}
	if err != nil {
		return err
	}
	if owner != caller && !isSteward(role) {
		return errInsufficientRole
	}
	if owner == caller && platform == "identity" {
		res, err := tx.Exec(`UPDATE key_envelopes SET alg=?,envelope=?,created_at=? WHERE container_id=? AND device_id=? AND key_generation=?`, v.Alg, env, now, cid, v.DeviceID, generation)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		if !isSteward(role) {
			return errInsufficientRole
		}
	}
	id, err := ids.Mint("env")
	if err != nil {
		return err
	}
	res, err := tx.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(container_id,device_id,key_generation) DO NOTHING`, id, cid, v.DeviceID, generation, v.Alg, env, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errEnvelopeExists
	}
	return nil
}
