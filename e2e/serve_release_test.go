//go:build !kye2e

package e2e

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/app"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestReleaseServeRefusesMultiBeforeOpeningStorage(t *testing.T) {
	t.Setenv("KYNOTES_TENANCY", "multi")
	err := app.Serve(context.Background(), config.Defaults(), logging.New(io.Discard, "info", "json"), "release")
	if err == nil || !strings.Contains(err.Error(), "multi is not available in this release") {
		t.Fatalf("Serve bypassed release gate: %v", err)
	}
}
