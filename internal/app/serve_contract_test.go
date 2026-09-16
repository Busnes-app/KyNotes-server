package app

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestServeRefusesToStartOnInvalidConfig(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "not-a-bind"
	err := Serve(context.Background(), c, logging.New(io.Discard, "info", "json"))
	if err == nil || !strings.Contains(err.Error(), "server.bind") {
		t.Fatalf("got %v", err)
	}
}

func TestGracefulShutdownDrainsInFlightRequest(t *testing.T) {
	c := config.Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:0"
	c.Server.DevInsecureCookies = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c, logging.New(io.Discard, "info", "json")) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
