package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestSetupHandlerDepositAndDrill(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Backup.Dir = t.TempDir()
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	createAdminUser(t, st.DB())
	service := backup.New(cfg, st, "test")
	t.Cleanup(service.Close)
	h := SetupHandler(SetupDeps{DB: st.DB(), Config: cfg, Backups: service, Version: "test", Log: logging.New(io.Discard, "info", "json")})
	call := func(path string) SocketResult {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		var out SocketResult
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return out
	}

	if out := call("/v1/deposit"); out.ErrorCode != "recovery_key_required" || string(out.Result) != "null" {
		t.Fatalf("unpinned deposit: %+v", out)
	}
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Pin("system", "test", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	out := call("/v1/deposit")
	var dep backup.Result
	if out.ErrorCode != "" || json.Unmarshal(out.Result, &dep) != nil || dep.Manifest.CapsuleID == "" {
		t.Fatalf("deposit: %+v", out)
	}
	if copies, _ := os.ReadDir(cfg.Backup.Dir); len(copies) != 1 {
		t.Fatalf("local copies: %d", len(copies))
	}
	out = call("/v1/backup-drill")
	if out.ErrorCode != "" || !strings.Contains(string(out.Result), `"passed":true`) {
		t.Fatalf("drill: %+v %s", out, out.Result)
	}

	// The service audits each run as it does for the admin route, attributed to the socket.
	var rows int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE actor_user_id=? AND request_id=?`, applysetup.Actor, SocketRequestID).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("socket audit rows: %d (%v); want failed deposit, deposit, drill", rows, err)
	}
}

func TestSetupHandlerOperationsWithoutBackupService(t *testing.T) {
	db, cfg := setupTestDB(t)
	h := SetupHandler(SetupDeps{DB: db, Config: cfg, Version: "test", Log: logging.New(io.Discard, "info", "json")})
	for _, path := range []string{"/v1/deposit", "/v1/backup-drill"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"error_code":"backup_unavailable"`) {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}
