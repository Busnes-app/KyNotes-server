package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busnes-app/ky-primitives/netallow"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

const exemptNetworksSetting = "rate_limit_exempt_networks"

// exemptNetworks is the live office-network allowlist: ratelimit.exempt_networks plus the
// admin setting. Requests from it skip the per-IP sign-in buckets only.
type exemptNetworks struct {
	env  string // canonical configured half, read-only in the admin screen
	list atomic.Pointer[netallow.List]
	save sync.Mutex // keeps the stored and the live list in step across concurrent saves
}

// loadExemptNetworks builds the list at startup. A stored value that cannot be read or no
// longer parses is dropped, leaving the configured list: fewer exemptions, never more.
func loadExemptNetworks(cfg config.Config, db *sql.DB, log *logging.Logger) *exemptNetworks {
	env, _ := netallow.Parse(strings.Join(cfg.RateLimit.ExemptNetworks, ",")) // config.Validate refused a bad one
	e := &exemptNetworks{env: env.String()}
	stored, err := storedExemptNetworks(db)
	var list *netallow.List
	if err == nil {
		list, err = e.combine(stored)
	}
	if err != nil {
		if log != nil {
			log.Warn("stored rate-limit exempt networks ignored", "event", "ratelimit.exempt_networks", "reason_code", "unreadable")
		}
		list, _ = e.combine("")
	}
	e.list.Store(list)
	return e
}

func (e *exemptNetworks) combine(stored string) (*netallow.List, error) {
	return netallow.Parse(e.env + "," + stored)
}

func storedExemptNetworks(db *sql.DB) (string, error) {
	if db == nil {
		return "", nil
	}
	var v string
	err := db.QueryRow(`SELECT value FROM server_settings WHERE key=?`, exemptNetworksSetting).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// exempt reports whether the request's client address, resolved exactly as the rate limiter
// resolves it (trusted proxies only), is on the list, and counts it if so.
func (e *exemptNetworks) exempt(r *http.Request, behindProxy bool, proxies []*net.IPNet) bool {
	if e == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(resolvedClientIP(r, behindProxy, proxies))
	return ok && e.list.Load().Exempt(addr)
}

func (e *exemptNetworks) status(stored string) map[string]any {
	return map[string]any{"networks": stored, "environment": e.env, "exempted": e.list.Load().Exempted()}
}

// ExemptNetworkRoutes serves the admin half of the allowlist. Changing it needs a step-up.
func ExemptNetworkRoutes(mux RouteMux, db *sql.DB, e *exemptNetworks) {
	mux.Handle("GET /api/v1/admin/rate-limit-networks", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stored, err := storedExemptNetworks(db)
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		writeJSON(w, e.status(stored))
	})))
	mux.Handle("PUT /api/v1/admin/rate-limit-networks", auth.RequireStepUp(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.CheckCSRF(r) != nil {
			WriteError(w, r, 403, "csrf_failed", "csrf validation failed")
			return
		}
		var in struct {
			Networks string `json:"networks"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in) != nil {
			WriteError(w, r, 400, "invalid_request", "invalid request")
			return
		}
		own, err := netallow.Parse(in.Networks)
		var combined *netallow.List
		if err == nil {
			combined, err = e.combine(own.String())
		}
		if err != nil {
			WriteError(w, r, 400, "invalid_request", strings.TrimPrefix(err.Error(), "netallow: "))
			return
		}
		stored := own.String()
		s, _ := auth.SessionFromContext(r)
		e.save.Lock()
		defer e.save.Unlock()
		// The setting and its audit row commit together; the live list changes only after both.
		err = dbTx(db, func(tx *sql.Tx) error {
			var previous string
			if err := tx.QueryRow(`SELECT value FROM server_settings WHERE key=?`, exemptNetworksSetting).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, exemptNetworksSetting, stored, time.Now().UTC().Format(time.RFC3339)); err != nil {
				return err
			}
			// Bounded: at most netallow.MaxEntries canonical networks on each side.
			return storage.RecordAuditOutcomeTx(tx, s.UserID, "admin.rate_limit_networks", "", "", "success", fmt.Sprintf("from=%q to=%q", previous, stored), RequestID(r))
		})
		if err != nil {
			WriteError(w, r, 500, "internal", "internal server error")
			return
		}
		e.list.Store(combined)
		writeJSON(w, e.status(stored))
	})))
}
