package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func registerSSOLogout(mux RouteMux, db *sql.DB, store *sso.Store, cfg config.Config) {
	failures := newLimiter()
	proxies := parseTrustedProxies(cfg.Server.TrustedProxies)
	reject := func(w http.ResponseWriter, r *http.Request, status int, message string) {
		limit := cfg.RateLimit.LoginPerMinute
		if !failures.allow(rateLimitClientIP(r, cfg.Server.BehindProxy, proxies), float64(limit)/60, limit, time.Now()) {
			w.Header().Set("Retry-After", "60")
			WriteError(w, r, 429, "rate_limited", "invalid logout requests rate limited")
			return
		}
		WriteError(w, r, status, "invalid_logout", message)
	}
	mux.HandleFunc("POST /api/v1/auth/oidc/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" {
			reject(w, r, 400, "form-encoded logout token required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err = r.ParseForm(); err != nil {
			status := 400
			var oversized *http.MaxBytesError
			if errors.As(err, &oversized) {
				status = 413
			}
			reject(w, r, status, "invalid logout request")
			return
		}
		values := r.PostForm["logout_token"]
		if len(values) != 1 || values[0] == "" {
			reject(w, r, 400, "one logout token required")
			return
		}
		settings := store.Load()
		c, err := store.VerifyLogout(r.Context(), settings, values[0])
		if err != nil {
			reject(w, r, 400, "invalid logout token")
			return
		}
		if err = auth.ApplySSOLogout(r.Context(), db, c, settings.ClientID, RequestID(r)); err != nil {
			if errors.Is(err, auth.ErrSSOLogoutRejected) {
				WriteError(w, r, 400, "invalid_logout", "invalid logout token")
			} else {
				WriteError(w, r, 500, "logout_failed", "logout was not committed")
			}
			return
		}
		auditLogoutOrg(db, settings.IssuerURL, c.Subject, values[0], RequestID(r))
		writeJSON(w, map[string]string{"status": "logged_out"})
	})
}

// auditLogoutOrg: in multi mode a logout token whose org_id is missing or not the account's
// still ends the sessions (logout only takes access away) and is audited auth.sso_org_mismatch
// (tenancy spec, Back-channel logout). The token's signature is already verified; only its
// org_id claim is read here.
func auditLogoutOrg(db *sql.DB, issuer, subject, token, requestID string) {
	tenancy, err := storage.TenancyOf(db)
	if err != nil || !tenancy.Multi() || subject == "" {
		return
	}
	var account string
	if db.QueryRow(`SELECT org_id FROM users WHERE sso_issuer=? AND sso_subject=?`, issuer, subject).Scan(&account) != nil {
		return
	}
	var claims struct {
		OrgID string `json:"org_id"`
	}
	if parts := strings.Split(token, "."); len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(payload, &claims)
		}
	}
	if claims.OrgID != account {
		recordAuditOutcome(db, "", "auth.sso_org_mismatch", "", subject, "success", "logout_applied", requestID)
	}
}
