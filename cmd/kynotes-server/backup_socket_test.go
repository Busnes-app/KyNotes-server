package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/applysetup"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// deposit and backup-drill run offline when the server is stopped and over the admin
// socket when it is running; both paths use the same backup service.
func TestDepositAndDrillOfflineAndLive(t *testing.T) {
	dir := t.TempDir()
	backups := filepath.Join(dir, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "kynotes.yaml")
	yaml := "data_dir: " + dir + "\nserver:\n  bind: 127.0.0.1:0\n  dev_insecure_cookies: true\nbackup:\n  dir: " + backups + "\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(filepath.Join(dir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	svc := backup.New(c, st, "test")
	err = svc.Pin("system", "test", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3)
	svc.Close()
	if err == nil {
		now := time.Now().UTC().Format(time.RFC3339)
		_, err = st.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,created_at,updated_at) VALUES('usr_a','admin','x','salt',600000,'admin','admin','active',?,?)`, now, now)
	}
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	copies := func() int {
		entries, _ := os.ReadDir(backups)
		return len(entries)
	}

	if err := capsuleCommand("deposit", []string{"--config", cfgPath}); err != nil || copies() != 1 {
		t.Fatalf("offline deposit: %v, %d copies", err, copies())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, c, logging.New(io.Discard, "info", "json"), "e2e") }()
	t.Cleanup(func() { cancel(); <-done })
	sock := app.AdminSocketPath(dir)
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.Dial("unix", sock); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The server holds the data-dir lock, so success here means the socket path ran.
	if err := capsuleCommand("deposit", []string{"--config", cfgPath}); err != nil || copies() != 2 {
		t.Fatalf("live deposit: %v, %d copies", err, copies())
	}
	var out bytes.Buffer
	if err := socketOperation(sock, "backup-drill", &out); err != nil || !strings.Contains(out.String(), `"passed":true`) {
		t.Fatalf("live drill: %v %s", err, out.String())
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "kynotes.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE actor_user_id=? AND request_id=?`, applysetup.Actor, httpapi.SocketRequestID).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("socket audit rows: %d (%v)", rows, err)
	}
}

func TestSocketOperationReportsServiceError(t *testing.T) {
	_, _, dataDir := setupCLIFixture(t)
	fakeSetupServer(t, dataDir, 200, `{"result":null,"error_code":"recovery_key_required"}`)
	var out bytes.Buffer
	if err := socketOperation(app.AdminSocketPath(dataDir), "deposit", &out); err == nil || err.Error() != "recovery_key_required" || out.Len() != 0 {
		t.Fatalf("%v %q", err, out.String())
	}
	if err := socketOperation(filepath.Join(t.TempDir(), "admin.sock"), "deposit", &out); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("no server: %v", err)
	}
}
