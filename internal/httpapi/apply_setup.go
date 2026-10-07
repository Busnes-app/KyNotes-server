package httpapi

import (
	"context"
	"database/sql"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// applySSO stores the bundle's SSO settings only when none exist, after the same
// discovery check login uses. It writes through the router's store so login sees it now.
func applySSO(ctx context.Context, db *sql.DB, store *sso.Store, want applysetup.SSO) applysetup.Result {
	have, next := store.Load(), applysetup.WantSSO(want)
	res := applysetup.Result{Section: "sso", Status: applysetup.DecideSSO(have, next)}
	switch res.Status {
	case applysetup.Present:
		return res
	case applysetup.Conflict:
		res.Detail = applysetup.SSODiff(have, next)
		return res
	}
	if _, err := sso.DiscoverEndpoints(ctx, next.IssuerURL); err != nil {
		res.Status, res.Detail = applysetup.Invalid, "issuer metadata probe failed: "+err.Error()
		return res
	}
	if err := store.Save(next); err != nil {
		res.Status, res.Detail = applysetup.Failed, "storing SSO settings failed"
		return res
	}
	if err := storage.RecordAuditOutcome(db, applysetup.Actor, "admin.sso_update", "", "", "success", applysetup.RequestID, applysetup.RequestID); err != nil {
		res.Status, res.Detail = applysetup.Failed, "SSO settings stored but the audit row failed"
	}
	return res
}
