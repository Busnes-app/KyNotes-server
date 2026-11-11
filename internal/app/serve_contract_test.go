package app

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestServeRefusesToStartOnInvalidConfig(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "not-a-bind"
	err := Serve(context.Background(), c, logging.New(io.Discard, "info", "json"), "test")
	if err == nil || !strings.Contains(err.Error(), "server.bind") {
		t.Fatalf("got %v", err)
	}
}

func TestShutdownWaitsForRunningGC(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	gcPass = func(db *sql.DB, _ *blobstore.Store, _ time.Time, _ time.Duration, _ bool) (storage.GCStats, error) {
		once.Do(func() {
			close(started)
			time.Sleep(200 * time.Millisecond)
			if err := db.Ping(); err != nil {
				t.Error("GC ran against a closed store:", err)
			}
			close(finished)
		})
		return storage.GCStats{}, nil
	}
	t.Cleanup(func() { gcPass = storage.RunGC })
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	c.GC.Interval = "1ms"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(io.Discard, "info", "json"), "test") }()
	<-started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Serve returned while GC was still running")
	}
}

func TestGracefulShutdownDrainsInFlightRequest(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(io.Discard, "info", "json"), "test") }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Serve drains HTTP, reminder pushes, GC and the admin socket one after the other, each for up
// to shutdown_grace, then gives an interrupted backup backupDrain to record its outcome. The
// compose file must grant more than that worst case, or Docker's SIGKILL lands mid-drain.
func TestComposeGraceCoversShutdown(t *testing.T) {
	budget := 4*parse(config.Defaults().Server.ShutdownGrace) + backupDrain
	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*stop_grace_period:\s*(\S+)\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("docker-compose.yml sets no stop_grace_period; Docker's default 10s is shorter than the shutdown budget")
	}
	if grace := parse(string(m[1])); grace <= budget {
		t.Errorf("stop_grace_period %s does not cover the worst-case shutdown (%s)", m[1], budget)
	}
}
