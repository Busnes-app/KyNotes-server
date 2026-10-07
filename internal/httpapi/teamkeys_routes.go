package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

const envelopeAlg = "x25519-hkdf-sha256-chacha20poly1305"

var (
	errNotMember             = errors.New("not a member")
	errInsufficientRole      = errors.New("insufficient role")
	errEnvelopeInvalid       = errors.New("invalid envelope")
	errEnvelopeExists        = errors.New("envelope exists")
	errGenerationMoved       = errors.New("key generation changed")
	errKeyRotationIncomplete = errors.New("key rotation incomplete")
	errMembershipExists      = errors.New("membership exists")
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

// ownIdentityEnvelopeSQL is the shared save gate: the writer's own identity holds
// an envelope at the generation. Args: user, container, generation.
const ownIdentityEnvelopeSQL = `SELECT EXISTS(SELECT 1 FROM key_envelopes e JOIN devices d ON d.id=e.device_id AND d.platform='identity' AND d.revoked_at='' AND d.user_id=? WHERE e.container_id=? AND e.key_generation=?)`

// uncoveredIdentitiesSQL counts active members' identities without an envelope
// at the generation. Args: container, generation.
const uncoveredIdentitiesSQL = `SELECT COUNT(*) FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=?1 AND m.revoked_at='' JOIN users u ON u.id=d.user_id AND u.status='active' WHERE d.platform='identity' AND d.revoked_at='' AND NOT EXISTS(SELECT 1 FROM key_envelopes e WHERE e.container_id=?1 AND e.device_id=d.id AND e.key_generation=?2)`

func TeamKeyRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("POST /api/v1/containers/{id}/key-rotations", auth.RequireUserStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		var in struct {
			ExpectedGeneration int64        `json:"expectedGeneration"`
			Envelopes          []envelopeIn `json:"envelopes"`
		}
		if ids.Validate("cnt", cid) != nil || json.NewDecoder(r.Body).Decode(&in) != nil || in.ExpectedGeneration < 1 || len(in.Envelopes) == 0 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		seen := map[string]bool{}
		for _, v := range in.Envelopes {
			if seen[v.DeviceID] {
				WriteError(w, r, 400, "invalid_request", "invalid request")
				return
			}
			seen[v.DeviceID] = true
		}
		var next int64
		err := dbTx(db, func(tx *sql.Tx) error {
			now := time.Now().UTC()
			if err := auth.RecheckUserStepUpTx(tx, s, now); err != nil {
				return err
			}
			role, _, err := memberTx(tx, cid, s.UserID)
			if err != nil {
				return err
			}
			if !isSteward(role) {
				return errInsufficientRole
			}
			stamp := now.Format(time.RFC3339)
			err = tx.QueryRow(`UPDATE containers SET key_generation=key_generation+1,shared_generation=CASE WHEN shared_generation=0 THEN key_generation+1 ELSE shared_generation END,change_seq=change_seq+1,updated_at=? WHERE id=? AND key_generation=? RETURNING key_generation`, stamp, cid, in.ExpectedGeneration).Scan(&next)
			if errors.Is(err, sql.ErrNoRows) {
				return errGenerationMoved
			}
			if err != nil {
				return err
			}
			for _, v := range in.Envelopes {
				if err := insertEnvelopeTx(tx, cid, next, s.UserID, role, v, stamp); err != nil {
					if errors.Is(err, errGenerationMoved) {
						return errEnvelopeInvalid // the set must target the new generation
					}
					return err
				}
			}
			if _, err := tx.Exec(`DELETE FROM invitation_envelopes WHERE container_id=? AND key_generation<?`, cid, next); err != nil {
				return err
			}
			var uncovered int
			var own bool
			if err := tx.QueryRow(uncoveredIdentitiesSQL, cid, next).Scan(&uncovered); err != nil {
				return err
			}
			if err := tx.QueryRow(ownIdentityEnvelopeSQL, s.UserID, cid, next).Scan(&own); err != nil {
				return err
			}
			if uncovered > 0 || !own {
				return errEnvelopeInvalid
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "container.key_rotate", cid, "", "success", "", RequestID(r))
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		writeJSON(w, map[string]any{"keyGeneration": next})
	})))
	mux.Handle("PUT /api/v1/comments/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		id := r.PathValue("id")
		var in struct {
			BodyCiphertext string `json:"bodyCiphertext"`
			KeyGeneration  int64  `json:"keyGeneration"`
		}
		if ids.Validate("cmt", id) != nil || json.NewDecoder(r.Body).Decode(&in) != nil || in.KeyGeneration < 1 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		body, err := base64.StdEncoding.DecodeString(in.BodyCiphertext)
		if err != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		err = dbTx(db, func(tx *sql.Tx) error {
			var cid, author, role string
			err := tx.QueryRow(`SELECT c.container_id,c.author_user_id,m.role FROM comments c JOIN memberships m ON m.container_id=c.container_id AND m.user_id=? AND m.revoked_at='' WHERE c.id=? AND c.deleted_at=''`, s.UserID, id).Scan(&cid, &author, &role)
			if err != nil {
				return err
			}
			if author != s.UserID || role == "viewer" {
				return errInsufficientRole
			}
			if err := checkWriteGate(tx, cid, s.UserID, in.KeyGeneration); err != nil {
				return err
			}
			now := time.Now().UTC().Format(time.RFC3339)
			var seq int64
			if err := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); err != nil {
				return err
			}
			_, err = tx.Exec(`UPDATE comments SET body_ciphertext=?,key_generation=?,change_seq=? WHERE id=?`, body, in.KeyGeneration, seq, id)
			return err
		})
		if writeTeamKeyError(w, r, err) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	// Visible to the user, to anyone sharing a live container with them, and to a
	// team or project owner/admin holding a pending invitation for them. Everyone
	// else gets the same 404, so the route is no liveness oracle for strangers.
	mux.Handle("GET /api/v1/users/{id}/identity", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		target := r.PathValue("id")
		if ids.Validate("usr", target) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var deviceID, publicKey, fingerprint string
		err := db.QueryRow(`SELECT d.id,d.public_key,d.fingerprint FROM devices d JOIN users u ON u.id=d.user_id AND u.status='active' WHERE d.user_id=?1 AND d.platform='identity' AND d.revoked_at='' AND (?1=?2
 OR EXISTS(SELECT 1 FROM memberships a JOIN memberships b ON b.container_id=a.container_id AND b.user_id=?1 AND b.revoked_at='' JOIN containers c ON c.id=a.container_id AND c.deleted_at='' WHERE a.user_id=?2 AND a.revoked_at='')
 OR EXISTS(SELECT 1 FROM invitations i JOIN containers c ON c.id=i.container_id AND c.deleted_at='' AND c.kind IN ('team','project') JOIN memberships a ON a.container_id=i.container_id AND a.user_id=?2 AND a.revoked_at='' AND a.role IN ('owner','admin') WHERE i.invitee_id=?1 AND i.inviter_id=?2 AND i.status='pending' AND i.expires_at>?3))`, target, s.UserID, time.Now().UTC().Format(time.RFC3339)).Scan(&deviceID, &publicKey, &fingerprint)
		if errors.Is(err, sql.ErrNoRows) {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]string{"userId": target, "deviceId": deviceID, "publicKey": publicKey, "fingerprint": fingerprint})
	})))
}

// missingEnvelopesSQL is the legacy save gate for containers that never rotated
// (shared_generation=0): members' paired devices lacking an envelope at the
// current generation. Identity rows are excluded.
const missingEnvelopesSQL = `SELECT COUNT(*) FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' WHERE d.revoked_at='' AND d.platform<>'identity' AND NOT EXISTS(SELECT 1 FROM key_envelopes e WHERE e.container_id=? AND e.device_id=d.id AND e.key_generation=?)`

type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// checkWriteGate admits a content write by userID into cid at generation
// requested. Containers that never rotated keep the legacy device rule; once
// rotated, the writer's own identity needs an envelope at the current generation.
// Call it before streaming a body and again inside the write transaction.
func checkWriteGate(q rowQuerier, cid, userID string, requested int64) error {
	var generation, shared int64
	err := q.QueryRow(`SELECT c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id AND m.user_id=? AND m.revoked_at='' WHERE c.id=?`, userID, cid).Scan(&generation, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return errNotMember
	}
	if err != nil {
		return err
	}
	if requested != generation {
		return errKeyRotationIncomplete
	}
	admitted := false
	if shared == 0 {
		var missing int
		err = q.QueryRow(missingEnvelopesSQL, cid, cid, generation).Scan(&missing)
		admitted = missing == 0
	} else {
		err = q.QueryRow(ownIdentityEnvelopeSQL, userID, cid, generation).Scan(&admitted)
	}
	if err != nil {
		return err
	}
	if !admitted {
		return errKeyRotationIncomplete
	}
	return nil
}

// removeMemberTx revokes target from team cid and its child workspaces, bumps
// their key generations and deletes target's envelopes and device selections
// there. Owners are never removed; sql.ErrNoRows when nothing was revoked.
func removeMemberTx(tx *sql.Tx, cid, target string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(`UPDATE memberships SET revoked_at=? WHERE container_id=? AND user_id=? AND role<>'owner' AND revoked_at=''`, now, cid, target)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	const scope = `(SELECT id FROM containers WHERE id=?1 OR team_id=?1)`
	for _, q := range []string{
		`UPDATE memberships SET revoked_at=?3 WHERE container_id IN ` + scope + ` AND user_id=?2 AND revoked_at=''`,
		`UPDATE containers SET key_generation=key_generation+1,change_seq=change_seq+1,updated_at=?3 WHERE id=?1 OR (team_id=?1 AND deleted_at='')`,
		`DELETE FROM key_envelopes WHERE container_id IN ` + scope + ` AND device_id IN (SELECT id FROM devices WHERE user_id=?2)`,
		`DELETE FROM device_containers WHERE container_id IN ` + scope + ` AND device_id IN (SELECT id FROM devices WHERE user_id=?2)`,
		// The removed steward's pending invitations die with them (envelopes cascade).
		`DELETE FROM invitations WHERE container_id IN ` + scope + ` AND inviter_id=?2 AND status='pending'`,
		`DELETE FROM invitation_envelopes WHERE container_id IN ` + scope + ` AND key_generation<(SELECT key_generation FROM containers c WHERE c.id=invitation_envelopes.container_id)`,
	} {
		if _, err := tx.Exec(q, cid, target, now); err != nil {
			return err
		}
	}
	return nil
}

type invitationEnvelopeIn struct {
	ContainerID string `json:"containerId"`
	envelopeIn
}

// insertInvitationEnvelopeTx stores an envelope for the invitee's identity in
// team cid or one of its child workspaces, at that container's current
// generation, where the inviter is owner or admin. One per container.
func insertInvitationEnvelopeTx(tx *sql.Tx, invitationID, cid, inviter, invitee string, v invitationEnvelopeIn) error {
	env, ok := v.bytes()
	if !ok || ids.Validate("cnt", v.ContainerID) != nil {
		return errEnvelopeInvalid
	}
	var role string
	var generation int64
	err := tx.QueryRow(`SELECT m.role,c.key_generation FROM containers c JOIN memberships m ON m.container_id=c.id AND m.user_id=? AND m.revoked_at='' WHERE c.id=? AND (c.id=? OR c.team_id=?) AND c.deleted_at=''`, inviter, v.ContainerID, cid, cid).Scan(&role, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return errEnvelopeInvalid
	}
	if err != nil {
		return err
	}
	if !isSteward(role) {
		return errInsufficientRole
	}
	if v.KeyGeneration != generation {
		return errGenerationMoved
	}
	var identity int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM devices WHERE id=? AND user_id=? AND platform='identity' AND revoked_at=''`, v.DeviceID, invitee).Scan(&identity); err != nil {
		return err
	}
	if identity == 0 {
		return errEnvelopeInvalid
	}
	res, err := tx.Exec(`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`, invitationID, v.ContainerID, v.DeviceID, v.KeyGeneration, v.Alg, env)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errEnvelopeInvalid // a second envelope for the same container
	}
	return nil
}

// moveInvitationEnvelopesTx installs an accepted invitation's envelopes whose
// container is still at their generation and whose identity is still live; the
// rest are dropped for the key steward sweep to fill.
func moveInvitationEnvelopesTx(tx *sql.Tx, invitationID, invitee, now string) error {
	rows, err := tx.Query(`SELECT ie.container_id,ie.device_id,ie.key_generation,ie.alg,ie.envelope FROM invitation_envelopes ie JOIN containers c ON c.id=ie.container_id AND c.key_generation=ie.key_generation AND c.deleted_at='' JOIN devices d ON d.id=ie.device_id AND d.user_id=? AND d.platform='identity' AND d.revoked_at='' WHERE ie.invitation_id=?`, invitee, invitationID)
	if err != nil {
		return err
	}
	type moved struct {
		container, device, alg string
		generation             int64
		envelope               []byte
	}
	var all []moved
	for rows.Next() {
		var m moved
		if err := rows.Scan(&m.container, &m.device, &m.generation, &m.alg, &m.envelope); err != nil {
			rows.Close()
			return err
		}
		all = append(all, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range all {
		id, err := ids.Mint("env")
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(container_id,device_id,key_generation) DO NOTHING`, id, m.container, m.device, m.generation, m.alg, m.envelope, now); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`DELETE FROM invitation_envelopes WHERE invitation_id=?`, invitationID)
	return err
}
