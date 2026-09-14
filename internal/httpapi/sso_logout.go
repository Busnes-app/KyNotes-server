package httpapi

import (
	"database/sql"
	"errors"
	"mime"
	"net/http"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/sso"
)

func registerSSOLogout(mux *http.ServeMux, db *sql.DB, store *sso.Store) {
	mux.HandleFunc("POST /api/v1/auth/oidc/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" {
			WriteError(w, r, 400, "invalid_logout", "form-encoded logout token required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err = r.ParseForm(); err != nil {
			status := 400
			var oversized *http.MaxBytesError
			if errors.As(err, &oversized) {
				status = 413
			}
			WriteError(w, r, status, "invalid_logout", "invalid logout request")
			return
		}
		values := r.PostForm["logout_token"]
		if len(values) != 1 || values[0] == "" {
			WriteError(w, r, 400, "invalid_logout", "one logout token required")
			return
		}
		settings := store.Load()
		c, err := store.VerifyLogout(r.Context(), settings, values[0])
		if err != nil {
			WriteError(w, r, 400, "invalid_logout", "invalid logout token")
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
