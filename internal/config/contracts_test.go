package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	c := Defaults()
	c.DataDir = t.TempDir()
	c.Server.Bind = "127.0.0.1:8080"
	c.Server.DevInsecureCookies = true
	return c
}

func TestLoadDefaultsMatchExampleFile(t *testing.T) {
	c := Defaults()
	if c.Server.Bind == "" || c.Limits.ChunkBytes <= 0 || c.Limits.AttachmentMaxBytes < c.Limits.ChunkBytes {
		t.Fatal("defaults are incomplete")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_SERVER_BIND", "127.0.0.1:9090")
	c, err := Load(path)
	if err != nil || c.Server.Bind != "127.0.0.1:9090" {
		t.Fatalf("env override failed: %v %#v", err, c.Server)
	}
}

func TestMissingDataDirIsRefused(t *testing.T) {
	c := testConfig(t)
	c.DataDir = filepath.Join(c.DataDir, "missing")
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("got %v", err)
	}
}

func TestUnwritableDataDirIsRefused(t *testing.T) {
	c := testConfig(t)
	file := filepath.Join(c.DataDir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c.DataDir = file
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("got %v", err)
	}
}

func TestInsecureCookiesRefusedOnNonLoopbackBind(t *testing.T) {
	c := testConfig(t)
	c.Server.Bind = "0.0.0.0:8080"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "dev_insecure_cookies") {
		t.Fatalf("got %v", err)
	}
}

func TestShortPairingSecretIsRefused(t *testing.T) {
	c := testConfig(t)
	c.Secrets.PairingSecret = "short"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "pairing_secret") {
		t.Fatalf("got %v", err)
	}
}

func TestShortServerSaltKeyIsRefused(t *testing.T) {
	c := testConfig(t)
	c.Secrets.ServerSaltKey = "short"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "server_salt_key") {
		t.Fatalf("got %v", err)
	}
}

func TestChunkSizeLargerThanAttachmentLimitIsRefused(t *testing.T) {
	c := testConfig(t)
	c.Limits.ChunkBytes = c.Limits.AttachmentMaxBytes + 1
	if err := Validate(c); err == nil {
		t.Fatal("oversized chunk accepted")
	}
}

func TestGCRetentionBelowOneHourIsRefused(t *testing.T) {
	c := testConfig(t)
	c.GC.Retention = "59m"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "gc.retention") {
		t.Fatalf("got %v", err)
	}
}

func TestBehindProxyWithoutTrustedProxiesIsRefused(t *testing.T) {
	c := testConfig(t)
	c.Server.BehindProxy = true
	c.Server.TrustedProxies = nil
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
		t.Fatalf("got %v", err)
	}
}

func TestUnparseableDurationIsRefused(t *testing.T) {
	c := testConfig(t)
	c.Server.ReadTimeout = "not-a-duration"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "read_timeout") {
		t.Fatalf("got %v", err)
	}
}

func TestValidationErrorNamesTheOffendingKey(t *testing.T) {
	c := testConfig(t)
	c.Server.Bind = "invalid"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "server.bind") {
		t.Fatalf("got %v", err)
	}
}

func TestDisallowedFieldIsDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("data_dir: " + dir + "\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\npassword: leaked\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidByteEnvironmentValueIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_SERVER_MAX_REQUEST_BYTES", "not-a-number")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "max_request_bytes") {
		t.Fatalf("got %v", err)
	}
}

func TestRateLimitEnvRejectsInvalidAndNegative(t *testing.T) {
	for _, v := range []string{"abc", "-1", "1.5"} {
		t.Setenv("KYNOTES_RATELIMIT_INVITATION_PER_HOUR", v)
		c := Defaults()
		if err := applyEnv(&c); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
	t.Setenv("KYNOTES_RATELIMIT_INVITATION_PER_HOUR", "0")
	c := Defaults()
	if err := applyEnv(&c); err != nil || c.RateLimit.InvitationPerHour != 0 {
		t.Fatalf("0 (off): %v %d", err, c.RateLimit.InvitationPerHour)
	}
	c.RateLimit.UploadPerMinute = -1
	c.DataDir = t.TempDir()
	if err := Validate(c); err == nil {
		t.Fatal("negative yaml limit accepted")
	}
}
