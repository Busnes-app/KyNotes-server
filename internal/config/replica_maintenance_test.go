package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplicaMaintenanceReadsEnvironmentWithoutMintingOrEnablingStartup(t *testing.T) {
	t.Setenv("KYNOTES_SERVER_BIND", "127.0.0.1:8080")
	t.Setenv("KYNOTES_SERVER_DEV_INSECURE_COOKIES", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := "data_dir: " + dir + "\nratelimit:\n  login_per_minute: 19\nsecrets:\n  pairing_secret: " + strings.Repeat("x", 32) + "\n  server_salt_key: " + strings.Repeat("y", 32) + "\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_TENANCY", "single")
	if _, err := LoadReplicaMaintenance(path); err == nil {
		t.Fatal("single maintenance accepted")
	}
	t.Setenv("KYNOTES_TENANCY", "multi")
	t.Setenv("KYNOTES_SECRETS_PAIRING_SECRET", "")
	t.Setenv("KYNOTES_SECRETS_SERVER_SALT_KEY", "")
	if _, err := LoadReplicaMaintenance(path); err == nil {
		t.Fatal("file keys used as environment fallback")
	}
	t.Setenv("KYNOTES_SECRETS_PAIRING_SECRET", strings.Repeat("p", 32))
	t.Setenv("KYNOTES_SECRETS_SERVER_SALT_KEY", strings.Repeat("s", 32))
	c, err := LoadReplicaMaintenance(path)
	if err != nil || c.RateLimit.LoginPerMinute != 19 || c.Secrets.PairingSecret != strings.Repeat("p", 32) {
		t.Fatalf("maintenance config: %+v %v", c.RateLimit, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "config.yaml" {
		t.Fatal("maintenance wrote local state", err)
	}
	for _, load := range []func(string) (Config, error){Load, LoadExisting} {
		if _, err := load(path); err == nil {
			t.Fatal("maintenance lifted ordinary startup refusal")
		}
	}
	if err := os.WriteFile(path, []byte(raw+"backup:\n  blob_target:\n    url: s3://bucket\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReplicaMaintenance(path); err == nil {
		t.Fatal("multi accepted append-only single-mode mirror")
	}
}
