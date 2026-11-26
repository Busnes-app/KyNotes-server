//go:build !kye2e

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseBuildRefusesMultiTenant(t *testing.T) {
	if multiTenantBuild {
		t.Fatal("release build must keep multiTenantBuild false")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"KYNOTES_TENANCY":                 "multi",
		"KYNOTES_STAFF_ORG_ID":            "org-staff",
		"KYNOTES_REGION":                  "e2e-1",
		"KYNOTES_DB_DSN":                  "postgres://notes:pw@db/notes",
		"KYNOTES_SSO_ISSUER":              "https://id.e2e.test",
		"KYNOTES_SSO_CLIENT_ID":           "kynotes",
		"KYNOTES_SSO_CLIENT_SECRET":       "secret",
		"KYNOTES_SSO_HMAC_SECRET":         strings.Repeat("h", 32),
		"KYNOTES_SECRETS_PAIRING_SECRET":  strings.Repeat("p", 32),
		"KYNOTES_SECRETS_SERVER_SALT_KEY": strings.Repeat("s", 32),
	} {
		t.Setenv(k, v)
	}
	const want = "KYNOTES_TENANCY: multi is not available in this release"
	for name, check := range map[string]func() error{
		"Load":         func() error { _, err := Load(path); return err },
		"LoadExisting": func() error { _, err := LoadExisting(path); return err },
		"Bind":         func() error { _, err := Bind(path); return err },
		"DataDir":      func() error { _, err := DataDir(path); return err },
	} {
		err := check()
		if err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %q", name, err, want)
		}
	}
}
