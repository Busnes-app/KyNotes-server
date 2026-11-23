package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Carry request cancellation through the existing quota and authorization row-query contracts.
type staffRows struct {
	ctx context.Context
	tx  *sql.Tx
}

func (s staffRows) QueryRow(query string, args ...any) *sql.Row {
	return s.tx.QueryRowContext(s.ctx, query, args...)
}

var errStaffReadDenied = errors.New("staff read no longer authorized")

// Every staff directory/audit response commits its platform audit before publishing metadata.
// Recheck the caller under the same writer transaction so a revoked administrator reads nothing.
func staffRead(w http.ResponseWriter, r *http.Request, db *sql.DB, org, surface string, read func(*sql.Tx) (any, error)) {
	s, _ := auth.SessionFromContext(r)
	var out any
	err := func() error {
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if role, err := auth.SessionRole(staffRows{r.Context(), tx}, s); err != nil || role != "admin" {
			return errStaffReadDenied
		}
		if org != "" {
			var n int
			if err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM orgs WHERE id=?`, org).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				return sql.ErrNoRows
			}
		}
		if out, err = read(tx); err != nil {
			return err
		}
		if err := storage.RecordAuditOutcomeTx(tx, s.UserID, "staff.read", "", org, "success", "surface="+surface, RequestID(r)); err != nil {
			return err
		}
		return tx.Commit()
	}()
	switch {
	case errors.Is(err, errStaffReadDenied):
		WriteError(w, r, 403, "forbidden", "staff access required")
	case errors.Is(err, sql.ErrNoRows):
		WriteError(w, r, 404, "not_found", "not found")
	case err != nil:
		WriteError(w, r, 500, "internal", "staff read unavailable")
	default:
		writeJSON(w, out)
	}
}
func staffOrgQuery(w http.ResponseWriter, r *http.Request, required bool) (string, bool) {
	values := r.URL.Query()["org"]
	if len(values) > 1 || len(values) == 1 && len(values[0]) > 128 {
		WriteError(w, r, 400, "invalid_request", "invalid org selection")
		return "", false
	}
	org := ""
	if len(values) == 1 {
		org = values[0]
	}
	if required && org == "" {
		WriteError(w, r, 400, "org_required", "select an org")
		return "", false
	}
	return org, true
}

// Return false only for single mode, whose handler and response shape remain unchanged.
func serveStaffUsers(w http.ResponseWriter, r *http.Request, db *sql.DB) bool {
	tenancy, err := storage.TenancyOfContext(r.Context(), db)
	if err != nil {
		WriteError(w, r, 500, "internal", "staff read unavailable")
		return true
	}
	if !tenancy.Multi() {
		return false
	}
	org, ok := staffOrgQuery(w, r, true)
	if !ok {
		return true
	}
	staffRead(w, r, db, org, "users", func(tx *sql.Tx) (any, error) {
		rows, err := tx.QueryContext(r.Context(), `SELECT id,username,role,account_kind,status,quota_bytes,created_at FROM users WHERE org_id=? ORDER BY username`, org)
		if err != nil {
			return nil, err
		}
		out := []map[string]any{}
		for rows.Next() {
			var id, username, role, kind, status, created string
			var quota int64
			if err := rows.Scan(&id, &username, &role, &kind, &status, &quota, &created); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, map[string]any{"id": id, "username": username, "role": role, "accountKind": kind, "status": status, "quotaBytes": quota, "createdAt": created})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, u := range out {
			used, err := userChargedBytes(staffRows{r.Context(), tx}, u["id"].(string), "")
			if err != nil {
				return nil, err
			}
			u["usedBytes"] = used
		}
		return out, nil
	})
	return true
}
func serveStaffAudit(w http.ResponseWriter, r *http.Request, db *sql.DB) bool {
	tenancy, err := storage.TenancyOfContext(r.Context(), db)
	if err != nil {
		WriteError(w, r, 500, "internal", "staff read unavailable")
		return true
	}
	if !tenancy.Multi() {
		return false
	}
	org, ok := staffOrgQuery(w, r, false)
	if !ok {
		return true
	}
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n < 501 {
		limit = n
	}
	staffRead(w, r, db, org, "audit", func(tx *sql.Tx) (any, error) {
		scope := "org_id IS NULL"
		args := []any{limit}
		if org != "" {
			scope = "org_id=?"
			args = []any{org, limit}
		}
		rows, err := tx.QueryContext(r.Context(), `SELECT event,outcome,actor_user_id,container_id,object_id,reason_code,at FROM audit_history WHERE `+scope+` ORDER BY at DESC,id DESC LIMIT ?`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []map[string]string{}
		for rows.Next() {
			var event, outcome, actor, container, object, reason, at string
			if err := rows.Scan(&event, &outcome, &actor, &container, &object, &reason, &at); err != nil {
				return nil, err
			}
			out = append(out, map[string]string{"event": event, "outcome": outcome, "actorUserId": actor, "containerId": container, "objectId": object, "reasonCode": reason, "at": at})
		}
		return out, rows.Err()
	})
	return true
}
func registerStaffOrgs(mux RouteMux, db *sql.DB, cfg config.Config) {
	mux.Handle("GET /api/v1/admin/orgs", auth.RequireAdmin(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenancy, err := storage.TenancyOfContext(r.Context(), db)
		if err != nil {
			WriteError(w, r, 500, "internal", "staff read unavailable")
			return
		}
		if !tenancy.Multi() {
			WriteError(w, r, 404, "not_found", "not found")
			return
		}
		staffRead(w, r, db, "", "orgs", func(tx *sql.Tx) (any, error) {
			rows, err := tx.QueryContext(r.Context(), `SELECT o.id,o.status,o.revision,o.enabled,o.home_region,o.seen_at,o.purged_at,COALESCE(p.ceiling_bytes,0),COALESCE(p.expires_at,''),COALESCE(p.pool_bytes,0),COALESCE(p.org_used_bytes,0),p.over_since,COALESCE(p.attempted_at,'') FROM orgs o LEFT JOIN org_pool p ON p.org_id=o.id ORDER BY o.id`)
			if err != nil {
				return nil, err
			}
			out := []map[string]any{}
			for rows.Next() {
				var id, status, region, seen, purged, expires, attempted string
				var revision, ceiling, pool, orgUsed int64
				var enabled bool
				var over sql.NullInt64
				if err := rows.Scan(&id, &status, &revision, &enabled, &region, &seen, &purged, &ceiling, &expires, &pool, &orgUsed, &over, &attempted); err != nil {
					rows.Close()
					return nil, err
				}
				var overSince any
				if over.Valid {
					overSince = over.Int64
				}
				out = append(out, map[string]any{"id": id, "status": status, "revision": revision, "enabled": enabled, "homeRegion": region, "lastPoll": seen, "purgedAt": purged, "ceilingBytes": ceiling, "grantExpiresAt": expires, "poolBytes": pool, "orgUsedBytes": orgUsed, "overSince": overSince, "lastReportAttempt": attempted, "userQuotaBytes": cfg.Limits.UserQuotaBytes, "teamQuotaBytes": cfg.Limits.TeamQuotaBytes})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, err
			}
			for _, o := range out {
				used, err := storage.OrgChargedBytes(db, staffRows{r.Context(), tx}, o["id"].(string), "")
				if err != nil {
					return nil, err
				}
				o["notesUsedBytes"] = used
			}
			return out, nil
		})
	})))
}
