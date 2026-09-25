package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/web"
)

func NewRouter(log *logging.Logger, max int64, ready func() bool, extras ...any) http.Handler {
	mux := http.NewServeMux()
	var db *sql.DB
	var blobs *blobstore.Store
	var cfg config.Config
	var backups *backup.Service
	for _, extra := range extras {
		switch v := extra.(type) {
		case *sql.DB:
			db = v
		case *blobstore.Store:
			blobs = v
		case *backup.Service:
			backups = v
		case config.Config:
			cfg = v
		}
	}
	if db != nil {
		ssoStore := sso.NewStore(db)
		AuthRoutes(mux, db, cfg)
		SSORoutes(mux, db, cfg, ssoStore)
		AdminRoutes(mux, db, ssoStore)
		if backups != nil {
			BackupRoutes(mux, db, backups)
		}
		ContainerRoutes(mux, db)
		SyncRoutes(mux, db)
		CollabRoutes(mux, db)
		PushRoutes(mux, db)
		DeviceRoutes(mux, db, cfg)
		if blobs != nil {
			ObjectRoutes(mux, db, blobs, cfg.Limits.ObjectMaxBytes)
			ShareLinkRoutes(mux, db, blobs)
			UploadRoutes(mux, db, blobs, cfg)
		}
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready() {
			WriteError(w, r, 503, "unavailable", "service is not ready")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	})
	static := web.Handler()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/manifest.webmanifest" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/favicon.svg" && r.URL.Path != "/favicon.png" && r.URL.Path != "/app-icon.png" && r.URL.Path != "/app-icon-192.png" && r.URL.Path != "/app-icon-512.png" && !strings.HasPrefix(r.URL.Path, "/share/") && !strings.HasPrefix(r.URL.Path, "/assets/") && !strings.HasPrefix(r.URL.Path, "/fonts/") && !strings.HasPrefix(r.URL.Path, "/auth/") {
			WriteError(w, r, http.StatusNotFound, "not_found", "not found")
			return
		}
		static.ServeHTTP(w, r)
	}))
	proxies := parseTrustedProxies(cfg.Server.TrustedProxies)
	return SecurityHeaders(MiddlewareWithProxies(log, max, proxies)(AccessLog(log, rateLimitMiddleware(cfg, db, mux))))
}
