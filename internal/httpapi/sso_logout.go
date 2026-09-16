package httpapi

import (
	"database/sql"
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func registerSSOLogout(mux *http.ServeMux, db *sql.DB, store *sso.Store, cfg config.Config) {
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
		writeJSON(w, map[string]string{"status": "logged_out"})
	})
}
