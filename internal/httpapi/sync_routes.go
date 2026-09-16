package httpapi

import (
	"database/sql"
	"encoding/base64"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"net/http"
	"strconv"
)

func SyncRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.Handle("GET /api/v1/containers/{id}/changes", auth.RequireEither(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := auth.CredentialUserID(r)
		device, isDevice := auth.DeviceFromContext(r)
		cid := r.PathValue("id")
		if ids.Validate("cnt", cid) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		var member int
		if db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, uid).Scan(&member) != nil || member == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		if isDevice {
			var selected int
			if db.QueryRow(`SELECT COUNT(*) FROM device_containers WHERE device_id=? AND container_id=?`, device.ID, cid).Scan(&selected) != nil || selected == 0 {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
		}
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 200
		}
		if limit > 1000 {
			limit = 1000
		}
		rows, e := db.Query(`SELECT id,'object',change_seq,deleted_at, routing_ciphertext FROM objects WHERE container_id=? AND change_seq>? UNION ALL SELECT id,'attachment',change_seq,deleted_at, x'' FROM attachments WHERE container_id=? AND change_seq>? UNION ALL SELECT id,'comment',change_seq,deleted_at, x'' FROM comments WHERE container_id=? AND change_seq>? UNION ALL SELECT id,'conflict',change_seq,resolved_at, x'' FROM conflicts WHERE container_id=? AND change_seq>? ORDER BY change_seq LIMIT ?`, cid, since, cid, since, cid, since, cid, since, limit)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		next := since
		for rows.Next() {
			var id, kind, deleted string
			var routing []byte
			var seq int64
			if rows.Scan(&id, &kind, &seq, &deleted, &routing) != nil {
				continue
			}
			if seq > next {
				next = seq
			}
			entry := map[string]any{"id": id, "kind": kind, "changeSeq": seq, "deleted": deleted != ""}
			if kind == "object" && len(routing) > 0 {
				entry["routingCiphertext"] = base64.StdEncoding.EncodeToString(routing)
			}
			out = append(out, entry)
		}
		writeJSON(w, map[string]any{"changes": out, "nextCursor": strconv.FormatInt(next, 10), "hasMore": len(out) == limit})
	})))
}
