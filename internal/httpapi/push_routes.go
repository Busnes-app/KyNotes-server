package httpapi

import (
	"database/sql"
	"encoding/json"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"net/http"
	"strings"
	"sync"
	"time"
)

type presenceEntry struct {
	UserID      string
	ContainerID string
	State       string
	At          time.Time
}

var presenceMu sync.Mutex
var presence = map[string]presenceEntry{}

func PushPayload(containerID string, changeSeq int64) []byte {
	b, _ := json.Marshal(map[string]any{"type": "kynotes.changes", "containerId": containerID, "changeSeq": changeSeq})
	return b
}

func PushRoutes(mux RouteMux, db *sql.DB) {
	mux.Handle("GET /api/v1/notifications", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := auth.SessionFromContext(r)
		rows, err := db.Query(`SELECT c.id,c.object_id,c.author_user_id,c.created_at FROM mentions n JOIN comments c ON c.id=n.comment_id WHERE n.mentioned_user_id=? AND c.deleted_at='' ORDER BY c.created_at DESC LIMIT 100`, s.UserID)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var id, objectID, author, created string
			if rows.Scan(&id, &objectID, &author, &created) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]string{"id": id, "objectId": objectID, "authorUserId": author, "createdAt": created, "kind": "mention"})
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})))
	mux.Handle("GET /api/v1/presence", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := strings.TrimSpace(r.URL.Query().Get("containerId"))
		s, _ := auth.SessionFromContext(r)
		var member int
		if db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, cid, s.UserID).Scan(&member) != nil || member == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		shared, err := storage.SharedMode(db)
		if err != nil {
			WriteError(w, r, 503, "unavailable", "presence unavailable")
			return
		}
		if shared {
			rows, err := db.QueryContext(r.Context(), `SELECT p.user_id,p.state FROM replica_presence p JOIN memberships m ON m.user_id=p.user_id AND m.container_id=p.container_id WHERE p.container_id=? AND p.expires_at>extract(epoch FROM clock_timestamp()) AND m.revoked_at='' ORDER BY p.user_id`, cid)
			if err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			defer rows.Close()
			out := []map[string]string{}
			for rows.Next() {
				var user, state string
				if err := rows.Scan(&user, &state); err != nil {
					WriteError(w, r, 500, "internal", "internal server error")
					return
				}
				out = append(out, map[string]string{"userId": user, "state": state})
			}
			if rows.Err() != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			writeJSON(w, out)
			return
		}
		now := time.Now()
		presenceMu.Lock()
		out := []map[string]string{}
		for _, entry := range presence {
			if entry.ContainerID == cid && now.Sub(entry.At) < 45*time.Second {
				out = append(out, map[string]string{"userId": entry.UserID, "state": entry.State})
			}
		}
		presenceMu.Unlock()
		writeJSON(w, out)
	})))
	mux.Handle("POST /api/v1/presence", auth.RequireSession(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			ContainerID string `json:"containerId"`
			State       string `json:"state"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.ContainerID == "" || (in.State != "editing" && in.State != "viewing" && in.State != "idle") {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var member int
		if db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=? AND revoked_at=''`, in.ContainerID, s.UserID).Scan(&member) != nil || member == 0 {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		shared, err := storage.SharedMode(db)
		if err != nil {
			WriteError(w, r, 503, "unavailable", "presence unavailable")
			return
		}
		if shared {
			res, err := db.ExecContext(r.Context(), `INSERT INTO replica_presence(user_id,container_id,state,expires_at) SELECT ?,?,?,floor(extract(epoch FROM clock_timestamp()))::bigint+45 WHERE EXISTS(SELECT 1 FROM memberships WHERE user_id=? AND container_id=? AND revoked_at='') ON CONFLICT(user_id,container_id) DO UPDATE SET state=excluded.state,expires_at=excluded.expires_at`, s.UserID, in.ContainerID, in.State, s.UserID, in.ContainerID)
			if err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			n, err := res.RowsAffected()
			if err != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			if n != 1 {
				WriteError(w, r, 404, "not_found", "not found")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		presenceMu.Lock()
		presence[s.UserID+"\x00"+in.ContainerID] = presenceEntry{UserID: s.UserID, ContainerID: in.ContainerID, State: in.State, At: time.Now()}
		presenceMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/sync/pending", auth.RequireDevice(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := auth.DeviceFromContext(r)
		rows, e := db.Query(`SELECT dc.container_id,c.change_seq FROM device_containers dc JOIN containers c ON c.id=dc.container_id WHERE dc.device_id=? AND c.deleted_at=''`, d.ID)
		if e != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var cid string
			var seq int64
			if rows.Scan(&cid, &seq) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"containerId": cid, "changeSeq": seq})
		}
		if rows.Err() != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, out)
	})))
	mux.Handle("POST /api/v1/push/registrations", auth.RequireDevice(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, 503, "unavailable", "push transport is unavailable")
	})))
}
