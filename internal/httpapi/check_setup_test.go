package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestSetupInspectionDoesNotCreateOrPromoteAccounts(t *testing.T) {
	db, cfg := setupTestDB(t)
	settings := sso.NewStore(db)
	want := applysetup.SSO{IssuerURL: "https://identity.example.test", ClientID: "notes", ClientSecret: "private-secret", RedirectURI: "https://notes.example.test/api/v1/auth/oidc/callback"}
	if err := settings.Save(applysetup.WantSSO(want)); err != nil {
		t.Fatal(err)
	}
	owner := applysetup.Admin{Issuer: want.IssuerURL, Subject: "owner-subject", Username: "owner-admin"}
	if result, _ := applyAdmin(db, cfg, want.IssuerURL, owner); result.Status != applysetup.Created {
		t.Fatal(result)
	}
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: settings, Log: logging.New(io.Discard, "info", "json")})
	var audits, users int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	inspect := func(wantOwner applysetup.Admin) applysetup.Report {
		t.Helper()
		raw, _ := json.Marshal(applysetup.Request{Version: 1, SSO: &want, Admins: []applysetup.Admin{wantOwner}})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/check-setup", bytes.NewReader(raw)))
		var report applysetup.Report
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return report
	}
	if r := inspect(owner); r.ExitCode() != 0 {
		t.Fatal(r)
	}
	absent := owner
	absent.Subject = "absent"
	absent.Username = "missing-admin"
	if r := inspect(absent); r.ExitCode() != applysetup.ExitConflict {
		t.Fatal("missing account passed", r)
	}
	if _, err := db.Exec(`UPDATE users SET role='user' WHERE sso_subject=?`, owner.Subject); err != nil {
		t.Fatal(err)
	}
	if r := inspect(owner); r.ExitCode() != applysetup.ExitConflict {
		t.Fatal("demoted account passed", r)
	}
	var afterAudits, afterUsers int
	_ = db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&afterAudits)
	_ = db.QueryRow(`SELECT count(*) FROM users`).Scan(&afterUsers)
	if audits != afterAudits || users != afterUsers {
		t.Fatal("inspection changed audit or accounts", afterAudits, afterUsers)
	}
	var role string
	if err := db.QueryRow(`SELECT role FROM users WHERE sso_subject=?`, owner.Subject).Scan(&role); err != nil || role != "user" {
		t.Fatal("inspection promoted", role, err)
	}
}

func TestSetupHandoverReportsBlobTarget(t *testing.T) {
	for _, url := range []string{"", "file:///mnt/backup/kynotes"} {
		db, cfg := setupTestDB(t)
		cfg.Backup.BlobTarget.URL = url
		h := SetupHandler(SetupDeps{DB: db, Config: cfg, SSO: sso.NewStore(db), Log: logging.New(io.Discard, "info", "json")})
		for _, path := range []string{"/v1/check-setup", "/v1/apply-setup"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader([]byte(`{"version":1}`))))
			var report applysetup.Report
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil || report.Handover.BlobTargetConfigured != (url != "") {
				t.Fatal(url, path, w.Code, w.Body.String())
			}
		}
	}
}
