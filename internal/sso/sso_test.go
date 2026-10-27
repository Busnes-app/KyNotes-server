package sso

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
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
		HMACSecret:    "hmac-key-abcdefgh",
	}

	if err := store.Save(testSettings); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	loaded := store.Load()
	if !loaded.Enabled || loaded.IssuerURL != "https://auth.example.com" || loaded.ClientID != "kynotes" || loaded.HMACSecret != "hmac-key-abcdefgh" {
		t.Fatalf("loaded settings mismatch: %+v", loaded)
	}

	// Verify reload from DB
	store2 := NewStore(db)
	loaded2 := store2.Load()
	if !loaded2.Enabled || loaded2.IssuerURL != "https://auth.example.com" || loaded2.HMACSecret != "hmac-key-abcdefgh" {
		t.Fatalf("reloaded settings mismatch: %+v", loaded2)
	}
}

func TestShortDirectorySecretIsRefusedNotRewritten(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "sso.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	store := NewStore(st.DB())
	base := SSOSettings{Enabled: true, IssuerURL: "https://auth.example.com", ClientID: "kynotes"}

	short := base
	short.HMACSecret = strings.Repeat("s", 15)
	if err := store.Save(short); !errors.Is(err, ErrShortDirectorySecret) {
		t.Fatalf("15-byte secret: %v", err)
	}
	if NewStore(st.DB()).Load().Enabled {
		t.Fatal("a refused secret saved the settings")
	}
	ok := base
	ok.HMACSecret = strings.Repeat("s", 16)
	if err := store.Save(ok); err != nil {
		t.Fatalf("16-byte secret: %v", err)
	}

	// A short secret stored before the floor is kept as is: other settings still save.
	if _, err := st.DB().Exec(`UPDATE server_settings SET value=? WHERE key='sso_hmac_secret'`, "old-short"); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	disabled := store.Load()
	disabled.Enabled = false
	if err := store.Save(disabled); err != nil {
		t.Fatalf("saving with the stored secret: %v", err)
	}
	if got := NewStore(st.DB()).Load(); got.HMACSecret != "old-short" || got.Enabled {
		t.Fatalf("stored secret rewritten: %+v", got)
	}
}
