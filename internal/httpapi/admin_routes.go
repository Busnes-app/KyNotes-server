package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

var supportedThemes = map[string]bool{"Dark Matter": true, "Light Matter": true, "Tropics": true, "Tropic Night": true, "Ocean": true, "Coffee": true, "White Cliffs": true, "Cyber Punk": true, "Neon Purple": true, "Space": true, "Sky": true, "Forest": true, "Sun": true, "Patina Ky": true, "Polished Ky": true}

func recordAudit(db *sql.DB, actor, event, container, object, requestID string) {
	recordAuditOutcome(db, actor, event, container, object, "success", "", requestID)
}

// recordAuditOutcome writes one flat audit row. outcome is "success" or
// "failure"; reason is operator-facing text already bounded by the caller and
// never a secret.
func recordAuditOutcome(db *sql.DB, actor, event, container, object, outcome, reason, requestID string) {
	_ = storage.RecordAuditOutcome(db, actor, event, container, object, outcome, reason, requestID)
}

// AdminRoutes exposes metadata-only administration. It never returns secrets,
// ciphertext, request bodies, or raw process logs.
func AdminRoutes(mux *http.ServeMux, db *sql.DB, ssoStore *sso.Store) {
	mux.Handle("POST /api/v1/admin/teams", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		s, _ := auth.SessionFromContext(r)
		var in struct {
			MetaCiphertext string `json:"metaCiphertext"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.MetaCiphertext) > 8192 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		meta, err := base64.StdEncoding.DecodeString(in.MetaCiphertext)
		if err != nil || len(meta) > 4096 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		teamID, _ := ids.Mint("cnt")
		membershipID, _ := ids.Mint("mem")
		now := time.Now().UTC().Format(time.RFC3339)
		if err = dbTx(db, func(tx *sql.Tx) error {
			if _, e := tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,meta_ciphertext,meta_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, teamID, "team", s.UserID, 1, meta, 0, now, now); e != nil {
				return e
			}
			_, e := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,?,?)`, membershipID, teamID, s.UserID, "owner", now)
			return e
		}); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "admin.team.create", teamID, "", r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]any{"id": teamID, "kind": "team", "ownerUserId": s.UserID, "metaCiphertext": in.MetaCiphertext, "metaVersion": 0, "changeSeq": 1, "keyGeneration": 1})
	})))
	mux.Handle("GET /api/v1/admin/teams", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`SELECT id,kind,owner_user_id,meta_ciphertext,meta_version,change_seq,key_generation FROM containers WHERE kind='team' AND deleted_at='' ORDER BY id`)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, kind, owner string
			var meta []byte
			var metaVersion, changeSeq, keyGeneration int64
			if rows.Scan(&id, &kind, &owner, &meta, &metaVersion, &changeSeq, &keyGeneration) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "kind": kind, "ownerUserId": owner, "metaCiphertext": base64.StdEncoding.EncodeToString(meta), "metaVersion": metaVersion, "changeSeq": changeSeq, "keyGeneration": keyGeneration})
		}
		writeJSON(w, out)
	})))
	mux.Handle("POST /api/v1/admin/teams/{id}/members", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct{ UserID, Role string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.UserID == "" || (in.Role != "admin" && in.Role != "editor" && in.Role != "commenter" && in.Role != "viewer") {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		membershipID, _ := ids.Mint("mem")
		now := time.Now().UTC().Format(time.RFC3339)
		if err := dbTx(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM containers WHERE id=? AND kind='team' AND deleted_at='') AND EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')`, membershipID, r.PathValue("id"), in.UserID, in.Role, now, r.PathValue("id"), in.UserID); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) SELECT 'mem_' || lower(hex(randomblob(12))),c.id,?, ?,? FROM containers c WHERE c.team_id=? AND c.deleted_at=''`, in.UserID, in.Role, now, r.PathValue("id"))
			return err
		}); err != nil {
			WriteError(w, r, 409, "already_exists", "unable to add member")
			return
		}
		s, _ := auth.SessionFromContext(r)
		recordAudit(db, s.UserID, "admin.team.member_add", r.PathValue("id"), in.UserID, r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("DELETE /api/v1/admin/teams/{id}/members/{userID}", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		if _, err := db.Exec(`UPDATE memberships SET revoked_at=? WHERE container_id=? AND user_id=? AND role<>'owner' AND revoked_at=''`, time.Now().UTC().Format(time.RFC3339), r.PathValue("id"), r.PathValue("userID")); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		s, _ := auth.SessionFromContext(r)
		recordAudit(db, s.UserID, "admin.team.member_remove", r.PathValue("id"), r.PathValue("userID"), r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/admin/users", auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			Username, AuthSecret, LoginSalt string
			Iterations                      int
			Role                            string `json:"role"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Username == "" || len(in.AuthSecret) != 64 || in.LoginSalt == "" || in.Iterations < 100000 || in.Iterations > 1000000 || (in.Role != "user" && in.Role != "admin") {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		hash, err := auth.HashAuthSecret(in.AuthSecret)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		id, _ := ids.Mint("usr")
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err = db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id, strings.ToLower(strings.TrimSpace(in.Username)), hash, in.LoginSalt, in.Iterations, in.Role, now, now); err != nil {
			WriteError(w, r, 409, "already_exists", "username already exists")
			return
		}
		s, _ := auth.SessionFromContext(r)
		recordAudit(db, s.UserID, "admin.user.create", "", id, r.Header.Get("X-Request-Id"))
		writeJSON(w, map[string]string{"id": id})
	})))
	mux.Handle("GET /api/v1/admin/settings", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var theme string
		if db.QueryRow(`SELECT value FROM server_settings WHERE key='default_theme'`).Scan(&theme) != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, map[string]string{"defaultTheme": theme})
	})))
	mux.Handle("PATCH /api/v1/admin/settings", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			DefaultTheme string `json:"defaultTheme"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || !supportedThemes[in.DefaultTheme] {
			WriteError(w, r, 400, "invalid_request", "invalid theme")
			return
		}
		if _, err := db.Exec(`UPDATE server_settings SET value=?,updated_at=? WHERE key='default_theme'`, in.DefaultTheme, time.Now().UTC().Format(time.RFC3339)); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/admin/users", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query(`SELECT id,username,role,status,quota_bytes,created_at FROM users ORDER BY username`)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, username, role, status, created string
			var quota int64
			if rows.Scan(&id, &username, &role, &status, &quota, &created) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]any{"id": id, "username": username, "role": role, "status": status, "quotaBytes": quota, "createdAt": created})
		}
		writeJSON(w, out)
	})))
	mux.Handle("PATCH /api/v1/admin/users/{id}", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		id := r.PathValue("id")
		var in struct {
			Role, Status string
			QuotaBytes   *int64
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		if in.Role != "admin" && in.Role != "user" {
			WriteError(w, r, 400, "invalid_request", "invalid role")
			return
		}
		if in.Status != "active" && in.Status != "disabled" {
			WriteError(w, r, 400, "invalid_request", "invalid status")
			return
		}
		if in.QuotaBytes == nil || *in.QuotaBytes < 0 {
			WriteError(w, r, 400, "invalid_request", "invalid quota")
			return
		}
		s, _ := auth.SessionFromContext(r)
		if id == s.UserID && (in.Role != "admin" || in.Status != "active") {
			WriteError(w, r, 400, "invalid_request", "cannot disable or demote the current administrator")
			return
		}
		if _, err := db.Exec(`UPDATE users SET role=?,status=?,quota_bytes=?,updated_at=? WHERE id=?`, in.Role, in.Status, *in.QuotaBytes, time.Now().UTC().Format(time.RFC3339), id); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		recordAudit(db, s.UserID, "admin.user.update", "", id, r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("POST /api/v1/admin/users/{id}/password", auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			NewAuthSecret, NewLoginSalt string
			Iterations                  int
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in.NewAuthSecret) != 64 || in.NewLoginSalt == "" || in.Iterations < 100000 || in.Iterations > 1000000 {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		hash, err := auth.HashAuthSecret(in.NewAuthSecret)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		if _, err = db.Exec(`UPDATE users SET auth_secret_hash=?,login_salt=?,login_iterations=?,updated_at=? WHERE id=?`, hash, in.NewLoginSalt, in.Iterations, time.Now().UTC().Format(time.RFC3339), r.PathValue("id")); err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		_, _ = db.Exec(`UPDATE sessions SET revoked_at=? WHERE user_id=?`, time.Now().UTC().Format(time.RFC3339), r.PathValue("id"))
		s, _ := auth.SessionFromContext(r)
		recordAudit(db, s.UserID, "admin.user.password_reset", "", r.PathValue("id"), r.Header.Get("X-Request-Id"))
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("GET /api/v1/admin/audit", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if value, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && value > 0 && value < 501 {
			limit = value
		}
		rows, err := db.Query(`SELECT event,outcome,actor_user_id,container_id,object_id,reason_code,at FROM audit_events ORDER BY at DESC LIMIT ?`, limit)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var event, outcome, actor, container, object, reason, at string
			if rows.Scan(&event, &outcome, &actor, &container, &object, &reason, &at) != nil {
				WriteError(w, r, 500, "internal", "internal server error")
				return
			}
			out = append(out, map[string]string{"event": event, "outcome": outcome, "actorUserId": actor, "containerId": container, "objectId": object, "reasonCode": reason, "at": at})
		}
		writeJSON(w, out)
	})))
	if ssoStore != nil {
		handleGetSSO := auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			settings := ssoStore.Load()
			writeJSON(w, settings)
		}))
		mux.Handle("GET /api/v1/admin/sso", handleGetSSO)
		mux.Handle("GET /api/admin/sso", handleGetSSO)

		handlePostSSO := auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.CheckCSRF(r) != nil {
				WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
				return
			}
			var in sso.SSOSettings
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				WriteError(w, r, 400, "invalid_request", "invalid request")
				return
			}
			if err := ssoStore.Save(in); err != nil {
				WriteError(w, r, 500, "internal", "failed to save SSO settings")
				return
			}
			s, _ := auth.SessionFromContext(r)
			recordAudit(db, s.UserID, "admin.sso_update", "", "", r.Header.Get("X-Request-Id"))
			writeJSON(w, in)
		}))
		mux.Handle("POST /api/v1/admin/sso", handlePostSSO)
		mux.Handle("POST /api/admin/sso", handlePostSSO)

		handlePairSSO := auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.CheckCSRF(r) != nil {
				WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
				return
			}
			var in struct {
				IssuerURL    string `json:"issuerUrl"`
				PairingToken string `json:"pairingToken"`
				CallbackURL  string `json:"callbackUrl,omitempty"`
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.IssuerURL == "" || in.PairingToken == "" {
				WriteError(w, r, 400, "invalid_request", "issuerUrl and pairingToken are required")
				return
			}

			callbackURL := in.CallbackURL
			if callbackURL == "" {
				scheme := "http"
				if isRequestSecure(r) {
					scheme = "https"
				}
				callbackURL = fmt.Sprintf("%s://%s/api/v1/sync/events", scheme, requestHost(r))
			}

			resp, err := sso.PairWithKySignOn(r.Context(), in.IssuerURL, in.PairingToken, callbackURL)
			if err != nil {
				WriteError(w, r, http.StatusBadRequest, "pairing_failed", err.Error())
				return
			}

			newSettings := sso.SSOSettings{
				Enabled:       true,
				IssuerURL:     strings.TrimRight(in.IssuerURL, "/"),
				ClientID:      "kynotes",
				ClientSecret:  "",
				RedirectURI:   "",
				AutoProvision: true,
				HMACSecret:    resp.HMACSecret,
			}

			if err := ssoStore.Save(newSettings); err != nil {
				WriteError(w, r, 500, "internal", "failed to save paired SSO settings")
				return
			}

			s, _ := auth.SessionFromContext(r)
			recordAudit(db, s.UserID, "admin.sso_pair", "", resp.SystemID, r.Header.Get("X-Request-Id"))
			writeJSON(w, map[string]any{
				"success":  true,
				"systemId": resp.SystemID,
				"settings": newSettings,
			})
		}))
		mux.Handle("POST /api/v1/admin/sso/pair", handlePairSSO)
		mux.Handle("POST /api/admin/sso/pair", handlePairSSO)
	}
}
