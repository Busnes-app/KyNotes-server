package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"net/http"
	"strings"
	"time"
)

func ContainerRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /api/v1/containers", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		device, isDevice := auth.DeviceFromContext(r)
		query := `SELECT c.id,c.kind,c.team_id,c.meta_ciphertext,c.meta_version,c.change_seq,c.key_generation FROM containers c JOIN memberships m ON m.container_id=c.id WHERE m.user_id=? AND m.revoked_at='' AND c.deleted_at=''`
		args := []any{uid}
		if isDevice {
			query = `SELECT c.id,c.kind,c.team_id,c.meta_ciphertext,c.meta_version,c.change_seq,c.key_generation FROM containers c JOIN memberships m ON m.container_id=c.id JOIN device_containers dc ON dc.container_id=c.id AND dc.device_id=? WHERE m.user_id=? AND m.revoked_at='' AND c.deleted_at=''`
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
			var version, seq, generation int64
			_ = rows.Scan(&id, &kind, &teamID, &meta, &version, &seq, &generation)
			out = append(out, map[string]any{"id": id, "kind": kind, "teamId": teamID, "metaCiphertext": base64.StdEncoding.EncodeToString(meta), "metaVersion": version, "changeSeq": seq, "keyGeneration": generation})
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
		meta, e := base64.StdEncoding.DecodeString(in.Meta)
		if e != nil || len(meta) > 4096 {
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
		e = dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,team_id,change_seq,meta_ciphertext,meta_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, in.Kind, s.UserID, in.TeamID, 1, meta, 0, now, now); e != nil {
				return e
			}
			if in.TeamID != "" {
				if _, e := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) SELECT ?,?,?,role,? FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, mem, id, s.UserID, now, in.TeamID, s.UserID); e != nil {
					return e
				}
				_, e = tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) SELECT 'mem_' || lower(hex(randomblob(12))),?,?,role,? FROM memberships WHERE container_id=? AND user_id<>? AND revoked_at=''`, id, s.UserID, now, in.TeamID, s.UserID)
				return e
			}
			_, e = tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,?,?)`, mem, id, s.UserID, "owner", now)
			return e
		})
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "container.create", id, "", r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]any{"id": id, "kind": in.Kind, "teamId": in.TeamID, "metaCiphertext": in.Meta, "metaVersion": 0, "changeSeq": 1, "keyGeneration": 1})
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
			Meta        string `json:"metaCiphertext"`
			BaseVersion int64  `json:"baseVersion"`
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
		var cur int64
		if db.QueryRow(`SELECT meta_version FROM containers WHERE id=?`, cid).Scan(&cur) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if cur != in.BaseVersion {
			WriteError(w, r, 409, "version_conflict", "base version is stale")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		var seq int64
		if e = dbTx(db, func(tx *sql.Tx) error {
			if e := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,meta_ciphertext=?,meta_version=?,updated_at=? WHERE id=? RETURNING change_seq`, meta, cur+1, now, cid).Scan(&seq); e != nil {
				return e
			}
			return nil
		}); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]any{"metaVersion": cur + 1, "changeSeq": seq})
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
		var role string
		if db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&role) != nil {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if role != "owner" {
			WriteError(w, r, 403, "forbidden", "insufficient role")
			return
		}
		if time.Since(s.CreatedAt) >= 5*time.Minute {
			WriteError(w, r, 403, "forbidden", "re-authentication required")
			return
		}
		if _, e := db.Exec(`UPDATE containers SET deleted_at=?,change_seq=change_seq+1,updated_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), cid); e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
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
