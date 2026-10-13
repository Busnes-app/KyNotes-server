package httpapi

import (
	"context"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
)

// checkSetup reads the running SSO store and current identity bindings. Missing
// sections are conflicts; inspection never creates accounts, grants, audit or pins.
func checkSetup(ctx context.Context, d SetupDeps, req applysetup.Request) applysetup.Report {
	var results []applysetup.Result
	have := d.SSO.Load()
	if req.SSO != nil {
		status := applysetup.DecideSSO(have, applysetup.WantSSO(*req.SSO))
		if status == applysetup.Created {
			status = applysetup.Conflict
		}
		results = append(results, applysetup.Result{Section: "sso", Status: status})
	}
	var names []string
	for _, want := range req.Admins {
		r := applysetup.Result{Section: "admin:" + strings.ToLower(want.Username), Status: applysetup.Conflict}
		if have.IssuerURL == "" || have.IssuerURL != want.Issuer {
			r.Status = applysetup.Invalid
		} else {
			tx, err := d.DB.BeginTx(ctx, nil)
			if err != nil {
				r.Status = applysetup.Failed
			} else {
				account, err := lookupAccount(tx, `SELECT id,username,role,status,account_kind FROM users WHERE sso_issuer=? AND sso_subject=?`, want.Issuer, want.Subject)
				_ = tx.Rollback()
				if err != nil {
					r.Status = applysetup.Failed
				} else if account != nil && account.Role == "admin" && account.Status == "active" && account.Kind == "admin" {
					r.Status = applysetup.Present
					names = append(names, account.Username)
				}
			}
		}
		results = append(results, r)
	}
	h := applysetup.Handover{URL: applysetup.Origin(have.RedirectURI), AdminUsernames: names, BackupDir: d.Config.Backup.Dir, Version: d.Version}
	if d.Backups != nil {
		if req.Backup != nil {
			results = append(results, d.Backups.CheckSetup(*req.Backup)...)
		}
		h.RecoveryKeyFingerprint, _ = d.Backups.KeyID()
	} else if req.Backup != nil {
		results = append(results, applysetup.Result{Section: "backup", Status: applysetup.Failed})
	}
	return applysetup.NewReport(results, h)
}
