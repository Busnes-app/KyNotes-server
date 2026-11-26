//go:build kye2e

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EBuildMultiTenantGate(t *testing.T) {
	if !multiTenantBuild {
		t.Fatal("kye2e build must set multiTenantBuild true")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setMultiEnv := func(t *testing.T, issuer string) {
		t.Helper()
		for k, v := range map[string]string{
			"KYNOTES_TENANCY":                 "multi",
			"KYNOTES_STAFF_ORG_ID":            "org-staff",
			"KYNOTES_REGION":                  "e2e-1",
			"KYNOTES_DB_DSN":                  "postgres://notes:pw@db/notes",
			"KYNOTES_SSO_ISSUER":              issuer,
			"KYNOTES_SSO_CLIENT_ID":           "kynotes",
			"KYNOTES_SSO_CLIENT_SECRET":       "secret",
			"KYNOTES_SSO_HMAC_SECRET":         strings.Repeat("h", 32),
			"KYNOTES_SECRETS_PAIRING_SECRET":  strings.Repeat("p", 32),
			"KYNOTES_SECRETS_SERVER_SALT_KEY": strings.Repeat("s", 32),
		} {
			t.Setenv(k, v)
		}
	}

	for _, issuer := range []string{
		"https://id.e2e.test",
		"https://ID.E2E.TEST/",
		"https://id.e2e.test:8443",
		"https://auth.staging.test",
	} {
		t.Run("accepts_"+issuer, func(t *testing.T) {
			setMultiEnv(t, issuer)
			if _, err := Load(path); err != nil {
				t.Fatalf("Load(%q): %v", issuer, err)
			}
			if _, err := Bind(path); err != nil {
				t.Fatalf("Bind(%q): %v", issuer, err)
			}
			if _, err := DataDir(path); err != nil {
				t.Fatalf("DataDir(%q): %v", issuer, err)
			}
		})
	}

	for _, issuer := range []string{
		"",
		"http://id.e2e.test",
		"https://auth.example.com",
		"https://test",
		"https://.test",
		"https://id.test.example",
		"https://id.e2e.test.",
		"https://idtest",
		"https://user:pass@id.e2e.test",
		"https://id.e2e.test?a=1",
		"https://id.e2e.test#frag",
		"://bad",
	} {
		t.Run("refuses_"+issuer, func(t *testing.T) {
			setMultiEnv(t, issuer)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), "under .test") {
				t.Fatalf("Load(%q): got %v, want .test issuer refusal", issuer, err)
			}
		})
	}

	t.Run("single_mode_still_refuses_multi_env", func(t *testing.T) {
		t.Setenv("KYNOTES_TENANCY", "single")
		t.Setenv("KYNOTES_SSO_ISSUER", "https://id.e2e.test")
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "KYNOTES_SSO_ISSUER: set only in multi-tenant mode") {
			t.Fatalf("single mode with multi env: got %v", err)
		}
	})
}
