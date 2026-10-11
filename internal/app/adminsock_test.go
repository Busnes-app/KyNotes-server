package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestAdminSocketIsPrivateAndReplacesOnlyStaleSockets(t *testing.T) {
	dir := t.TempDir()
	l, err := listenAdminSocket(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(AdminSocketPath(dir))
	if err != nil || st.Mode().Type() != fs.ModeSocket || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
	if l.Addr().Network() != "unix" {
		t.Fatal(l.Addr().Network())
	}
	// A crash leaves the socket file behind.
	l.(peerListener).Listener.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l2, err := listenAdminSocket(dir)
	if err != nil {
		t.Fatal("stale socket not replaced:", err)
	}
	l2.Close()
	if _, err := os.Lstat(AdminSocketPath(dir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after close")
	}
	if err := os.WriteFile(AdminSocketPath(dir), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAdminSocket(dir); err == nil {
		t.Fatal("replaced a regular file")
	}
	if b, _ := os.ReadFile(AdminSocketPath(dir)); string(b) != "keep" {
		t.Fatal("regular file changed")
	}
}

func TestServeOwnsAdminSocketLifecycle(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(io.Discard, "info", "json"), "test") }()
	sock := AdminSocketPath(c.DataDir)
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
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("socket left after shutdown")
	}
}

// Serving a database whose administrators all became everyday accounts logs the CLI remedy.
func TestServeWarnsWithoutAdmin(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(c.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_plain','plain','h','s',1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	st.Close()
	var logged bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(&logged, "info", "json"), "test") }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if conn, err := net.Dial("unix", AdminSocketPath(c.DataDir)); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logged.String(), "no_active_admin") || !strings.Contains(logged.String(), "user add --admin") {
		t.Fatalf("no warning logged: %s", logged.String())
	}
}
