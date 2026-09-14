package sso

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kynotes-server/internal/storage"
)

func TestPKCE(t *testing.T) {
	v, c, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("unexpected error generating PKCE: %v", err)
	}
	if len(v) == 0 || len(c) == 0 {
		t.Fatalf("expected non-empty verifier and challenge")
	}
	if v == c {
		t.Fatalf("challenge should be hash of verifier")
	}
}

func TestGenerateState(t *testing.T) {
	s1 := GenerateState()
	s2 := GenerateState()
	if len(s1) != 32 || len(s2) != 32 {
		t.Fatalf("expected 32 hex chars, got %d and %d", len(s1), len(s2))
	}
	if s1 == s2 {
		t.Fatalf("states should be random and unique")
	}
}

func TestVerifyClaimsRefusesUnsignedIdentity(t *testing.T) {
	store := NewStore(nil)
	_, err := store.VerifyClaims(context.Background(), SSOSettings{IssuerURL: "https://issuer.example", ClientID: "kynotes"}, &DiscoveryDoc{JWKSURI: "https://issuer.example/keys"}, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", "nonce")
	if err == nil {
		t.Fatal("unsigned identity accepted")
	}
}

func TestStorePersistence(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "sso.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()

	store := NewStore(db)
	initial := store.Load()
	if initial.Enabled {
		t.Fatalf("expected initial SSO enabled to be false")
	}

	testSettings := SSOSettings{
		Enabled:       true,
		IssuerURL:     "https://auth.example.com",
		ClientID:      "kynotes",
		ClientSecret:  "secret123",
		RedirectURI:   "https://notes.example.com/api/v1/auth/oidc/callback",
		AutoProvision: true,
		HMACSecret:    "hmac-key-abc",
	}

	if err := store.Save(testSettings); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	loaded := store.Load()
	if !loaded.Enabled || loaded.IssuerURL != "https://auth.example.com" || loaded.ClientID != "kynotes" || loaded.HMACSecret != "hmac-key-abc" {
		t.Fatalf("loaded settings mismatch: %+v", loaded)
	}

	// Verify reload from DB
	store2 := NewStore(db)
	loaded2 := store2.Load()
	if !loaded2.Enabled || loaded2.IssuerURL != "https://auth.example.com" || loaded2.HMACSecret != "hmac-key-abc" {
		t.Fatalf("reloaded settings mismatch: %+v", loaded2)
	}
}
