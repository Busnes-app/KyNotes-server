package app

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func replicaEnvironment(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"KYNOTES_DB_DSN": "postgres://test@127.0.0.1/test?sslmode=disable", "KYNOTES_STAFF_ORG_ID": "org_staff", "KYNOTES_REGION": "eu",
		"KYNOTES_SECRETS_PAIRING_SECRET": strings.Repeat("p", 32), "KYNOTES_SECRETS_SERVER_SALT_KEY": strings.Repeat("s", 32),
		"KYNOTES_SSO_ISSUER": "https://identity.example", "KYNOTES_SSO_CLIENT_ID": "kynotes", "KYNOTES_SSO_CLIENT_SECRET": "client-secret", "KYNOTES_SSO_HMAC_SECRET": strings.Repeat("h", 32),
		"KYNOTES_VAPID_KEY":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"KYNOTES_BLOB_BACKEND": "object", "KYNOTES_BLOB_S3_ENDPOINT": "https://objects.example", "KYNOTES_BLOB_S3_BUCKET": "notes", "KYNOTES_BLOB_S3_REGION": "eu-test-1",
	} {
		t.Setenv(name, value)
	}
}
func TestReplicaKeysRequireEnvironmentAndCreateNoLocalFiles(t *testing.T) {
	replicaEnvironment(t)
	c := config.Defaults()
	c.DataDir = filepath.Join(t.TempDir(), "not-created")
	got, in, err := readReplicaInputs(c)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Tenancy.Multi() || !in.SSO.AutoProvision || got.Secrets.PairingSecret != strings.Repeat("p", 32) || in.VAPID == nil {
		t.Fatal("incomplete replica inputs")
	}
	fixed := sso.NewFixedStore(in.SSO)
	if fixed.Load() != in.SSO {
		t.Fatal("environment snapshot changed")
	}
	if err := fixed.Save(sso.SSOSettings{}); err != sso.ErrFixedSettings {
		t.Fatal("environment snapshot was writable")
	}
	if _, err := os.Stat(c.DataDir); !os.IsNotExist(err) {
		t.Fatalf("replica key input wrote a local directory: %v", err)
	}
	for _, name := range []string{"KYNOTES_SECRETS_PAIRING_SECRET", "KYNOTES_SECRETS_SERVER_SALT_KEY", "KYNOTES_VAPID_KEY", "KYNOTES_REGION", "KYNOTES_STAFF_ORG_ID", "KYNOTES_SSO_HMAC_SECRET"} {
		old := os.Getenv(name)
		t.Setenv(name, "")
		if _, _, err := readReplicaInputs(got); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("local fallback for %s: %v", name, err)
		}
		t.Setenv(name, old)
	}
	for name, value := range map[string]string{"KYNOTES_VAPID_KEY": "not-a-key", "KYNOTES_SSO_ISSUER": "http://identity.example", "KYNOTES_BLOB_S3_ENDPOINT": "http://objects.example", "KYNOTES_BLOB_BACKEND": "volume"} {
		old := os.Getenv(name)
		t.Setenv(name, value)
		if _, _, err := readReplicaInputs(got); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("unsafe %s accepted: %v", name, err)
		}
		t.Setenv(name, old)
	}
	t.Setenv("KYNOTES_TENANCY", "multi")
	if _, err := config.Load(filepath.Join(c.DataDir, "config.yaml")); err == nil {
		t.Fatal("replica preparation enabled multi startup")
	}
}

// KY_CELLS is the served cell list; KYNOTES_REGION names one cell. Every replica must list the
// same cells, in any order (the fingerprint).
func TestReplicaCellsAreReadAndFingerprinted(t *testing.T) {
	replicaEnvironment(t)
	c := config.Defaults()
	_, in, err := readReplicaInputs(c)
	if err != nil || !reflect.DeepEqual(in.Cells, []string{"eu"}) {
		t.Fatalf("KYNOTES_REGION as one cell: %v %v", in.Cells, err)
	}
	t.Setenv("KYNOTES_REGION", "")
	t.Setenv("KY_CELLS", "us-east-2,eu")
	_, a, err := readReplicaInputs(c)
	if err != nil || !reflect.DeepEqual(a.Cells, []string{"us-east-2", "eu"}) {
		t.Fatalf("KY_CELLS: %v %v", a.Cells, err)
	}
	t.Setenv("KY_CELLS", "eu,us-east-2")
	_, b, _ := readReplicaInputs(c)
	t.Setenv("KY_CELLS", "eu")
	_, one, _ := readReplicaInputs(c)
	if replicaFields(c, a)["cells"] != replicaFields(c, b)["cells"] || replicaFields(c, a)["cells"] == replicaFields(c, one)["cells"] {
		t.Fatal("the fingerprint must bind the set of cells, not their order")
	}
	for _, bad := range []string{"eu,eu", "EU", "eu/1"} {
		t.Setenv("KY_CELLS", bad)
		if _, _, err := readReplicaInputs(c); err == nil || !strings.Contains(err.Error(), "KY_CELLS") {
			t.Fatalf("KY_CELLS=%q: %v", bad, err)
		}
	}
	t.Setenv("KY_CELLS", "eu")
	t.Setenv("KYNOTES_REGION", "eu")
	if _, _, err := readReplicaInputs(c); err == nil {
		t.Fatal("KY_CELLS and KYNOTES_REGION both accepted")
	}
}

func TestReplicaFingerprintSeparatesSharedAndPerHostSettings(t *testing.T) {
	replicaEnvironment(t)
	c, in, err := readReplicaInputs(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	fields := replicaFields(c, in)
	local := c
	local.DataDir = "/another-host"
	local.Server.Bind = "127.0.0.1:9999"
	local.Server.TrustedProxies = []string{"192.0.2.1/32"}
	local.Backup.Dir = "/backups"
	local.Backup.Keep = 99
	local.Log.Level = "debug"
	if !reflect.DeepEqual(fields, replicaFields(local, in)) {
		t.Fatal("per-host configuration entered shared fingerprint")
	}
	changed := c
	changed.RateLimit.LoginPerMinute++
	if reflect.DeepEqual(fields, replicaFields(changed, in)) {
		t.Fatal("rate-limit difference omitted")
	}
	other := in
	other.Tenancy.StaffOrg = "org_other"
	if reflect.DeepEqual(fields, replicaFields(c, other)) {
		t.Fatal("staff-org difference omitted")
	}
	other = in
	other.BlobBucket = "other-bucket"
	if reflect.DeepEqual(fields, replicaFields(c, other)) {
		t.Fatal("bucket difference omitted")
	}
	for _, key := range []string{"tenancy_mode", "cells", "pairing_secret", "server_salt_key", "sso", "vapid_key", "server", "limits", "ratelimit", "gc", "backup_deposit_interval", "backup_allow_private_recovery", "strong_crypto", "blob_backend", "blob_endpoint", "blob_bucket", "blob_region"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("required shared field omitted: %s", key)
		}
	}
}
