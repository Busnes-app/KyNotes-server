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
	errStaleClient           = errors.New("stale client")
	errVersionConflict       = errors.New("version conflict")
)

// keySchemeHeader marks a write from a client that seals content only with container keys.
// Every content write and name change must carry it; a tab from an older build is refused
// and told to reload.
const keySchemeHeader, keySchemeShared = "X-Kynotes-Key-Scheme", "shared-v2"

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
	if err == nil {
		return false
	}
	status, code, message := teamKeyError(err)
	if code == "unauthenticated" || code == "step_up_required" {
		auth.WriteAuthError(w, code, message)
	} else {
		WriteError(w, r, status, code, message)
	}
	return true
}

// teamKeyError maps a team-key route error to its response; err is not nil.
func teamKeyError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, auth.ErrSessionInvalid):
		return 401, "unauthenticated", "authentication required"
	case errors.Is(err, auth.ErrStepUpInvalid):
		return 403, "step_up_required", "re-enter your password to continue"
	case errors.Is(err, auth.ErrPasswordAdminKnown):
		return 409, "password_change_required", "change the password an administrator set first"
	case errors.Is(err, errNotMember), errors.Is(err, sql.ErrNoRows):
		return 404, "not_found", "not found"
	case errors.Is(err, errInsufficientRole):
		return 403, "forbidden", "insufficient role"
	case errors.Is(err, errEnvelopeInvalid):
		return 400, "invalid_request", "invalid request"
	case errors.Is(err, errEnvelopeExists):
		return 409, "already_exists", "envelope already exists"
	case errors.Is(err, errGenerationMoved):
		return 409, "already_exists", "key generation changed"
	case errors.Is(err, errKeyRotationIncomplete):
		return 409, "already_exists", "key rotation incomplete"
	case errors.Is(err, errVersionConflict):
		return 409, "version_conflict", "base version is stale"
	case errors.Is(err, errStaleClient):
		return 409, "already_exists", "this notebook uses shared keys: reload the page"
	default:
		return 500, "internal", "internal server error"
	}
}

// auditRefusal records a failed membership attempt outside its rolled-back transaction. The reason
// is the response code, so the audit says no more than the caller was told.
func auditRefusal(db *sql.DB, r *http.Request, actor, event, container, object string, err error) {
	outcome, code := "denied", "already_exists"
	if !errors.Is(err, errMembershipExists) {
		var status int
		status, code, _ = teamKeyError(err)
		if status == 500 {
			outcome = "failure"
		}
	}
	recordAuditOutcome(db, actor, event, container, object, outcome, code, RequestID(r))
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
// role there). The recipient must be a live device or identity of an active,
// approved member; non-stewards may write only for their own. Insert-only: an existing
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
	err := tx.QueryRow(`SELECT d.user_id,d.platform FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=? AND m.revoked_at='' AND m.approved=1 JOIN users u ON u.id=d.user_id AND u.status='active' WHERE d.id=? AND d.revoked_at=''`, cid, v.DeviceID).Scan(&owner, &platform)
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

// putGenerationTx is the generation a PUT envelope targets: any generation from shared_generation
// to current that already holds an envelope, so stewards backfill history for newcomers. Keys are
// minted only by key-rotations, so a container without a key yet takes no envelope here.
func putGenerationTx(tx *sql.Tx, cid string, current, requested int64) (int64, error) {
	var shared int64
	if err := tx.QueryRow(`SELECT shared_generation FROM containers WHERE id=?`, cid).Scan(&shared); err != nil {
		return 0, err
	}
	if shared == 0 {
		return 0, errKeyRotationIncomplete
	}
	if requested < shared || requested > current {
		return 0, errGenerationMoved
	}
	var held bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM key_envelopes WHERE container_id=? AND key_generation=?)`, cid, requested).Scan(&held); err != nil {
		return 0, err
	}
	if !held {
		return 0, errKeyRotationIncomplete
	}
	return requested, nil
}

// ownIdentityEnvelopeSQL is the shared save gate: the writer's own identity holds
// an envelope at the generation. Args: user, container, generation.
const ownIdentityEnvelopeSQL = `SELECT EXISTS(SELECT 1 FROM key_envelopes e JOIN devices d ON d.id=e.device_id AND d.platform='identity' AND d.revoked_at='' AND d.user_id=? WHERE e.container_id=? AND e.key_generation=?)`

// uncoveredIdentitiesSQL counts active, approved members' identities without an envelope
// at the generation. Args: container, generation.
const uncoveredIdentitiesSQL = `SELECT COUNT(*) FROM devices d JOIN memberships m ON m.user_id=d.user_id AND m.container_id=?1 AND m.revoked_at='' AND m.approved=1 JOIN users u ON u.id=d.user_id AND u.status='active' WHERE d.platform='identity' AND d.revoked_at='' AND NOT EXISTS(SELECT 1 FROM key_envelopes e WHERE e.container_id=?1 AND e.device_id=d.id AND e.key_generation=?2)`

func TeamKeyRoutes(mux RouteMux, db *sql.DB) {
	mux.Handle("POST /api/v1/containers/{id}/key-rotations", auth.RequireUserActionStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if err := auth.RecheckUserActionTx(tx, s, now); err != nil {
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

type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// checkContainerKeyed admits bytes from userID into cid before any generation is named (upload
// start, chunks, preview finalize): a live member, sending keySchemeShared, into a container that
// has a key (shared_generation > 0). It returns the current generation.
func checkContainerKeyed(q rowQuerier, cid, userID, scheme string) (int64, error) {
	var generation, shared int64
	err := q.QueryRow(`SELECT c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id AND m.user_id=? AND m.revoked_at='' WHERE c.id=?`, userID, cid).Scan(&generation, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNotMember
	}
	if err != nil {
		return 0, err
	}
	if scheme != keySchemeShared {
		return 0, errStaleClient
	}
	if shared == 0 {
		return 0, errKeyRotationIncomplete
	}
	return generation, nil
}

// checkWriteGate admits a content write by userID into cid at generation requested: the container
// passes checkContainerKeyed, requested is its current generation and the writer's own identity
// holds an envelope there. Call it before streaming a body and again inside the write transaction.
func checkWriteGate(q rowQuerier, cid, userID string, requested int64, scheme string) error {
	generation, err := checkContainerKeyed(q, cid, userID, scheme)
	if err != nil {
		return err
	}
	if requested != generation {
		return errKeyRotationIncomplete
	}
	var admitted bool
	if err := q.QueryRow(ownIdentityEnvelopeSQL, userID, cid, generation).Scan(&admitted); err != nil {
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
		// Pending invitations to the removed member die too: accepting one must not undo the removal.
		`DELETE FROM invitations WHERE container_id IN ` + scope + ` AND invitee_id=?2 AND status='pending'`,
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

// retireKeysTx advances key_generation in every keyed container userID is a live, approved member of
// (an unapproved member never held a key), as a
// member removal does: a self-service reset may follow a stolen browser, so the old identity's
// keys must open nothing written afterwards. The new generation has no envelopes; writes wait
// until a steward mints it. It returns how many containers it retired.
func retireKeysTx(tx *sql.Tx, userID, now string) (int64, error) {
	const scope = `(SELECT container_id FROM memberships WHERE user_id=?1 AND revoked_at='' AND approved=1)`
	res, err := tx.Exec(`UPDATE containers SET key_generation=key_generation+1,change_seq=change_seq+1,updated_at=?2 WHERE shared_generation>0 AND deleted_at='' AND id IN `+scope, userID, now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM invitation_envelopes WHERE container_id IN `+scope+` AND key_generation<(SELECT key_generation FROM containers c WHERE c.id=invitation_envelopes.container_id)`, userID); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// admitMemberTx makes userID a member of cid and its live child workspaces with
// role, recording invitedBy (empty for a server-admin add). Rows a removal revoked
// are reactivated (the unique index keeps one row per container and user) and
// keep no keys; errMembershipExists when any row in the team scope is live.
// readmit reports that a revoked row came back. approved is false only for the
// server-admin add: that member holds the viewer role and no key until a steward
// approves it, and role is kept as its pending_role (0027_pending_viewer.sql).
func admitMemberTx(tx *sql.Tx, cid, userID, role, invitedBy string, approved bool, now string) (readmit bool, err error) {
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at='' AND container_id IN (SELECT id FROM containers WHERE id=?2 OR team_id=?2)`, userID, cid).Scan(&live); err != nil {
		return false, err
	}
	if live > 0 {
		return false, errMembershipExists
	}
	const scope = `(SELECT id FROM containers WHERE (id=?2 OR team_id=?2) AND deleted_at='')`
	effective, pending := role, ""
	if !approved {
		effective, pending = "viewer", role
	}
	for i, q := range []string{
		`UPDATE memberships SET role=?3,created_at=?4,revoked_at='',invited_by=?5,approved=?6,pending_role=?7 WHERE user_id=?1 AND container_id IN ` + scope,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at,invited_by,approved,pending_role) SELECT 'mem_' || lower(hex(randomblob(12))),c.id,?1,?3,?4,?5,?6,?7 FROM containers c WHERE c.id IN ` + scope + ` AND NOT EXISTS(SELECT 1 FROM memberships m WHERE m.container_id=c.id AND m.user_id=?1)`,
	} {
		res, err := tx.Exec(q, userID, cid, effective, now, invitedBy, approved, pending)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); i == 0 && n > 0 {
			readmit = true
		}
	}
	return readmit, nil
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
	var generation, shared int64
	err := tx.QueryRow(`SELECT m.role,c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id AND m.user_id=? AND m.revoked_at='' WHERE c.id=? AND (c.id=? OR c.team_id=?) AND c.deleted_at=''`, inviter, v.ContainerID, cid, cid).Scan(&role, &generation, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return errEnvelopeInvalid
	}
	if err != nil {
		return err
	}
	if !isSteward(role) {
		return errInsufficientRole
	}
	// Keys are minted only by key-rotations: a container without one takes no envelope.
	if shared == 0 {
		return errKeyRotationIncomplete
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
	rows, err := tx.Query(`SELECT ie.container_id,ie.device_id,ie.key_generation,ie.alg,ie.envelope FROM invitation_envelopes ie JOIN containers c ON c.id=ie.container_id AND c.key_generation=ie.key_generation AND c.shared_generation>0 AND c.deleted_at='' JOIN devices d ON d.id=ie.device_id AND d.user_id=? AND d.platform='identity' AND d.revoked_at='' WHERE ie.invitation_id=?`, invitee, invitationID)
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
