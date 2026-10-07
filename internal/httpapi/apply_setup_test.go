package httpapi

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestRouterUsesSuppliedSSOStore(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	h := NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true }, db, cfg, store)
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: "https://id.example", ClientID: "kynotes"}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/auth/sso-config", nil))
	if !strings.Contains(rec.Body.String(), `"issuerUrl":"https://id.example"`) {
		t.Fatalf("router served stale SSO settings: %s", rec.Body.String())
	}
}
