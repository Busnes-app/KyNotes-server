package httpapi

import (
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

const suiteAppsTTL = 60 * time.Second

// SuiteRoutes serves the app rail: the suite apps KyIdentity lets the signed-in SSO user open.
// Password sessions, unconfigured SSO and any KyIdentity failure answer an empty list.
func SuiteRoutes(mux RouteMux, db *sql.DB, settings *sso.Store) {
	cache := &suiteCache{entries: map[string]suiteEntry{}}
	mux.Handle("GET /api/v1/suite/apps", auth.RequireAccount(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		s, _ := auth.SessionFromContext(r)
		cfg := settings.Load()
		apps := []suitedir.App{}
		if cfg.Enabled && cfg.ClientSecret != "" && s.SSOSubject != "" && s.SSOIssuer == cfg.IssuerURL {
			// Keyed by account and everything that shapes the answer: never shared across users.
			key := s.UserID + "\x00" + cfg.IssuerURL + "\x00" + cfg.ClientID + "\x00" + s.SSOSubject
			if cached, ok := cache.get(key); ok {
				apps = cached
			} else if got, err := (&suitedir.Client{Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}).Apps(r.Context(), s.SSOSubject); err != nil {
				// suitedir errors carry neither the query (sub) nor the credentials.
				errorLog.Warn("suite apps unavailable", "request_id", RequestID(r), "event", "suite.apps", "error_kind", err.Error())
			} else {
				apps = got
				cache.put(key, got)
			}
		}
		writeJSON(w, map[string]any{"apps": apps})
	})))
}

type suiteEntry struct {
	apps  []suitedir.App
	until time.Time
}

type suiteCache struct {
	mu      sync.Mutex
	entries map[string]suiteEntry
}

func (c *suiteCache) get(key string) ([]suitedir.App, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e.apps, ok && time.Now().Before(e.until)
}

func (c *suiteCache) put(key string, apps []suitedir.App) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if !now.Before(e.until) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = suiteEntry{apps: apps, until: now.Add(suiteAppsTTL)}
}
