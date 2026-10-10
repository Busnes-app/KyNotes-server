package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"net/http"
	"strings"
	"time"
)

var errDeleteReauth = errors.New("re-authentication required")

func ContainerRoutes(mux RouteMux, db *sql.DB) {
	mux.Handle("GET /api/v1/containers", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		device, isDevice := auth.DeviceFromContext(r)
		query := `SELECT c.id,c.kind,c.team_id,c.meta_ciphertext,c.meta_version,c.change_seq,c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id WHERE m.user_id=? AND m.revoked_at='' AND c.deleted_at=''`
		args := []any{uid}
		if isDevice {
			query = `SELECT c.id,c.kind,c.team_id,c.meta_ciphertext,c.meta_version,c.change_seq,c.key_generation,c.shared_generation FROM containers c JOIN memberships m ON m.container_id=c.id JOIN device_containers dc ON dc.container_id=c.id AND dc.device_id=? WHERE m.user_id=? AND m.revoked_at='' AND c.deleted_at=''`
			args = []any{device.ID, uid}
		}
		rows, e := db.Query(query, args...)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, kind, teamID string
			var meta []byte
			var version, seq, generation, shared int64
			if e := rows.Scan(&id, &kind, &teamID, &meta, &version, &seq, &generation, &shared); e != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "kind": kind, "teamId": teamID, "metaCiphertext": base64.StdEncoding.EncodeToString(meta), "metaVersion": version, "changeSeq": seq, "keyGeneration": generation, "sharedGeneration": shared})
		}
		// A 200 is the complete list: clients treat a notebook missing from it as lost.
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})))
	mux.Handle("POST /api/v1/containers", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			Kind   string `json:"kind"`
			Meta   string `json:"metaCiphertext"`
			TeamID string `json:"teamId"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Kind != "workbook" && in.Kind != "project" && in.Kind != "team") {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		// A notebook has no name until its first key exists: the owner's browser seals it then.
		if in.Meta != "" {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if in.TeamID != "" {
			var role, teamKind string
			if db.QueryRow(`SELECT m.role,c.kind FROM memberships m JOIN containers c ON c.id=m.container_id WHERE m.container_id=? AND m.user_id=? AND m.revoked_at='' AND c.deleted_at=''`, in.TeamID, s.UserID).Scan(&role, &teamKind) != nil || teamKind != "team" || (role != "owner" && role != "admin") {
				WriteError(w, r, 403, "forbidden", "team workspace creation requires team administration")
				return
			}
			if in.Kind == "team" {
				WriteError(w, r, 400, "invalid_request", "team workspaces cannot be nested")
				return
			}
		}
		id, _ := ids.Mint("cnt")
		mem, _ := ids.Mint("mem")
		now := time.Now().UTC().Format(time.RFC3339)
		e := dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,team_id,change_seq,meta_ciphertext,meta_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, in.Kind, s.UserID, in.TeamID, 1, []byte{}, 0, now, now); e != nil {
				return e
			}
			if in.TeamID != "" {
				if _, e := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,invited_by,approved) SELECT ?,?,?,role,?,invited_by,approved FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, mem, id, s.UserID, now, in.TeamID, s.UserID); e != nil {
					return e
				}
				_, err := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,invited_by,approved) SELECT 'mem_' || lower(hex(randomblob(12))),?,user_id,role,?,invited_by,approved FROM memberships WHERE container_id=? AND user_id<>? AND revoked_at=''`, id, now, in.TeamID, s.UserID)
				return err
			}
			_, err := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,?,?)`, mem, id, s.UserID, "owner", now)
			return err
		})
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "container.create", id, "", r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]any{"id": id, "kind": in.Kind, "teamId": in.TeamID, "metaCiphertext": "", "metaVersion": 0, "changeSeq": 1, "keyGeneration": 1, "sharedGeneration": 0})
	})))
	mux.Handle("PATCH /api/v1/containers/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var in struct {
			Meta        string `json:"metaCiphertext"`
			BaseVersion int64  `json:"baseVersion"`
			// The generation the name was sealed with; required.
			KeyGeneration *int64 `json:"keyGeneration"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		meta, e := base64.StdEncoding.DecodeString(in.Meta)
		if e != nil || len(meta) > 4096 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		current := r.Header.Get(keySchemeHeader) == keySchemeShared
		now := time.Now().UTC().Format(time.RFC3339)
		var seq int64
		// Every check runs in the write transaction: a rename, rotation or removal
		// committed after the request arrived must refuse this write, not be overwritten.
		if e = dbTx(db, func(tx *sql.Tx) error {
			var role string
			var generation, shared int64
			if e := tx.QueryRow(`SELECT m.role,c.key_generation,c.shared_generation FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at=''`, cid, s.UserID).Scan(&role, &generation, &shared); e != nil {
				return e
			}
			if role != "owner" && role != "admin" && role != "editor" {
				return errInsufficientRole
			}
			if !current {
				return errStaleClient
			}
			// A name is sealed with the current generation only, so readers never need an older key;
			// a container without a key has no name to seal.
			if shared == 0 || in.KeyGeneration == nil || *in.KeyGeneration != generation {
				return errKeyRotationIncomplete
			}
			e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,meta_ciphertext=?,meta_version=meta_version+1,updated_at=? WHERE id=? AND meta_version=? RETURNING change_seq`, meta, now, cid, in.BaseVersion).Scan(&seq)
			if errors.Is(e, sql.ErrNoRows) {
				return errVersionConflict
			}
			return e
		}); e != nil {
			writeTeamKeyError(w, r, e)
			return
		}
		writeJSON(w, map[string]any{"metaVersion": in.BaseVersion + 1, "changeSeq": seq})
	})))
	mux.Handle("DELETE /api/v1/containers/{id}", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		e := dbTx(db, func(tx *sql.Tx) error {
			// blank: this user created it, still stewards it, and it was never keyed or named and holds
			// nothing (no rows of any kind, no invitations, no child notebooks; a team has no other active
			// member). Its creator may undo a failed creation at any time: there is nothing to lose.
			var role string
			var blank bool
			if e := tx.QueryRow(`SELECT m.role,c.owner_user_id=m.user_id AND m.role IN ('owner','admin') AND c.shared_generation=0 AND c.meta_version=0`+
				` AND NOT EXISTS(SELECT 1 FROM objects WHERE container_id=c.id) AND NOT EXISTS(SELECT 1 FROM comments WHERE container_id=c.id)`+
				` AND NOT EXISTS(SELECT 1 FROM attachments WHERE container_id=c.id) AND NOT EXISTS(SELECT 1 FROM upload_sessions WHERE container_id=c.id)`+
				` AND NOT EXISTS(SELECT 1 FROM key_envelopes WHERE container_id=c.id) AND NOT EXISTS(SELECT 1 FROM invitations WHERE container_id=c.id)`+
				` AND NOT EXISTS(SELECT 1 FROM containers t WHERE t.team_id=c.id AND t.deleted_at='')`+
				` AND (c.kind<>'team' OR NOT EXISTS(SELECT 1 FROM memberships o WHERE o.container_id=c.id AND o.user_id<>m.user_id AND o.revoked_at=''))`+
				` FROM memberships m JOIN containers c ON c.id=m.container_id AND c.deleted_at='' WHERE m.container_id=? AND m.user_id=? AND m.revoked_at=''`, cid, s.UserID).Scan(&role, &blank); e != nil {
				return e
			}
			if !blank && role != "owner" {
				return errInsufficientRole
			}
			if !blank && time.Since(s.CreatedAt) >= 5*time.Minute {
				return errDeleteReauth
			}
			now := time.Now().UTC().Format(time.RFC3339)
			reason := ""
			if blank {
				reason = "blank"
			}
			if _, e := tx.Exec(`UPDATE containers SET deleted_at=?,change_seq=change_seq+1,updated_at=? WHERE id=?`, now, now, cid); e != nil {
				return e
			}
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "container.delete", cid, "", "success", reason, RequestID(r))
		})
		if errors.Is(e, errDeleteReauth) {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		if writeTeamKeyError(w, r, e) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/containers/{id}/objects", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var role string
		if db.QueryRow(`SELECT m.role FROM memberships m WHERE m.container_id=? AND m.user_id=? AND m.revoked_at=''`, cid, s.UserID).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" && role != "admin" && role != "editor" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		var in struct {
			Kind string `json:"kind"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Kind != "note" && in.Kind != "folder") {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		id, _ := ids.Mint("obj")
		now := time.Now().UTC().Format(time.RFC3339)
		var seq int64
		if e := dbTx(db, func(tx *sql.Tx) error {
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? RETURNING change_seq`, now, cid).Scan(&seq); e != nil {
				return e
			}
			_, e := tx.Exec(`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES(?,?,?,?,?,?)`, id, cid, in.Kind, seq, now, now)
			return e
		}); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"id": id, "version": 0, "changeSeq": seq})
	})))
}
func dbTx(db *sql.DB, fn func(*sql.Tx) error) error {
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		_ = tx.Rollback()
		return e
	}
	return tx.Commit()
}

var _ = strings.TrimSpace
