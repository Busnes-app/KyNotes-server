package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRoutesRequireAdminStepUpAndCSRF(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()
	admin, _ := createAdminUser(t, db)
	rec := httptest.NewRecorder()
	session, err := auth.MintSession(db, rec, admin, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	service := backup.New(cfg, st, "test")
	mux := http.NewServeMux()
	BackupRoutes(mux, db, service)
	do := func(method, path string, body []byte, login, csrf bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/admin/backup/"+path, bytes.NewReader(body))
		if login {
			for _, c := range cookies {
				req.AddCookie(c)
			}
		}
		if csrf {
			req.Header.Set("X-CSRF-Token", session.CSRF)
		}
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}
	for _, path := range []string{"pin-key", "pair-remote", "unpair", "schedule", "drill", "mirror", "export-capsule"} {
		method := "POST"
		if got := do(method, path, []byte(`{}`), false, false); got.Code != 401 {
			t.Fatalf("%s anonymous %d", path, got.Code)
		}
		if got := do(method, path, []byte(`{}`), true, true); got.Code != 403 || !strings.Contains(got.Body.String(), "step_up_required") {
			t.Fatalf("%s stale step-up %d", path, got.Code)
		}
	}
	if _, err = db.Exec(`UPDATE sessions SET stepup_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), session.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"pin-key", "pair-remote", "unpair", "schedule", "deposit", "drill", "mirror", "export-capsule"} {
		if got := do("POST", path, []byte(`{}`), true, false); got.Code != 403 {
			t.Fatalf("%s no csrf %d", path, got.Code)
		}
	}
	if got := do("POST", "export-capsule", nil, true, true); got.Code != 412 {
		t.Fatalf("unpaired export %d %s", got.Code, got.Body.String())
	}
	if got := do("GET", "export-capsule", nil, true, false); got.Code != 405 {
		t.Fatalf("GET export accepted: %d", got.Code)
	}
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(key.Public().Bytes()), "threshold": 2, "total_shares": 3})
	if got := do("POST", "pin-key", body, true, true); got.Code != 204 {
		t.Fatalf("pin %d %s", got.Code, got.Body.String())
	}
	if got := do("POST", "deposit", nil, true, true); got.Code != 200 {
		t.Fatalf("run %d %s", got.Code, got.Body.String())
	}
	if got := do("POST", "export-capsule", nil, true, true); got.Code != 200 || got.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("export %d", got.Code)
	}
	if got := do("GET", "status", nil, true, false); got.Code != 200 || strings.Contains(got.Body.String(), cfg.Secrets.ServerSaltKey) {
		t.Fatalf("unsafe status: %d", got.Code)
	}
	if _, err = db.Exec(`UPDATE users SET role='user' WHERE id=?`, admin); err != nil {
		t.Fatal(err)
	}
	if got := do("GET", "status", nil, true, false); got.Code != 403 {
		t.Fatal("non-admin read backup status")
	}
}

// Deposit is admin plus CSRF only (suite parity); every other backup mutation keeps step-up.
func TestBackupDepositNeedsAdminNotStepUp(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()
	admin, _ := createAdminUser(t, db)
	rec := httptest.NewRecorder()
	session, err := auth.MintSession(db, rec, admin, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	service := backup.New(cfg, st, "test")
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Pin(admin, "test", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	BackupRoutes(mux, db, service)
	do := func(path string, csrf bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/admin/backup/"+path, strings.NewReader(`{}`))
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if csrf {
			req.Header.Set("X-CSRF-Token", session.CSRF)
		}
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}
	// The session has never stepped up.
	if got := do("deposit", false); got.Code != 403 || !strings.Contains(got.Body.String(), "csrf_failed") {
		t.Fatalf("deposit without csrf %d %s", got.Code, got.Body.String())
	}
	if got := do("deposit", true); got.Code != 200 {
		t.Fatalf("admin deposit without step-up %d %s", got.Code, got.Body.String())
	}
	if got := do("pair-remote", true); got.Code != 403 || !strings.Contains(got.Body.String(), "step_up_required") {
		t.Fatalf("pair-remote without step-up %d %s", got.Code, got.Body.String())
	}
	if _, err = db.Exec(`UPDATE users SET role='user' WHERE id=?`, admin); err != nil {
		t.Fatal(err)
	}
	if got := do("deposit", true); got.Code != 403 || strings.Contains(got.Body.String(), "result") {
		t.Fatalf("non-admin deposit %d %s", got.Code, got.Body.String())
	}
}
