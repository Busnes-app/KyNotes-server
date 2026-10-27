package config

import (
	"crypto/fips140"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlobTargetValidationAndEnv(t *testing.T) {
	for _, c := range []BlobTarget{{}, {URL: "file:///mnt/ciphertext"}, {URL: "s3://bucket/prefix", AccessKey: "id", Secret: "secret"}, {URL: "sftp://user@host/dir", Secret: "password", HostKey: "SHA256:verified"}} {
		if err := ValidateBlobTarget(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []BlobTarget{{URL: "ftp://host"}, {URL: "s3://bucket"}, {URL: "sftp://user@host/dir", Secret: "password"}, {URL: "sftp://user:DO_NOT_LEAK@host/dir", HostKey: "pin"}, {URL: "file://host/dir"}} {
		err := ValidateBlobTarget(c)
		if err == nil || strings.Contains(err.Error(), "DO_NOT_LEAK") {
			t.Fatal("invalid target accepted or secret leaked")
		}
	}
	t.Setenv("KYNOTES_BLOB_TARGET", "file:///override")
	t.Setenv("KYNOTES_BLOB_TARGET_SECRET", "")
	c := BlobTarget{URL: "file:///original"}
	applyBlobEnv(&c)
	if c.URL != "file:///override" {
		t.Fatal("env not applied")
	}
}

func TestOnlyProbeMayLoadUnpinnedSFTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "data_dir: " + t.TempDir() + "\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\nbackup:\n  blob_target:\n    url: sftp://fixture@localhost/vault\n    secret: synthetic\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("production accepted missing host pin")
	}
	cfg, err := LoadBlobTargetProbe(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backup.BlobTarget.HostKey != "" {
		t.Fatal("probe invented trust")
	}
}

// Under GODEBUG=fips140=on the mirror stays on SSH or TLS: SMB (NTLM) and plain-HTTP S3 are
// refused; without it they remain the documented explicit choices. CI runs both.
func TestStrongProfileRefusesNTLMAndPlainS3(t *testing.T) {
	t.Logf("fips140 profile enabled: %v", fips140.Enabled())
	for _, c := range []BlobTarget{
		{URL: "smb://host/share/dir", AccessKey: `DOMAIN\user`, Secret: "password"},
		{URL: "SMB://host/share/dir", AccessKey: `DOMAIN\user`, Secret: "password"},
		{URL: "s3://bucket/prefix", AccessKey: "id", Secret: "secret", S3Endpoint: "http://minio.lan:9000"},
	} {
		if err := ValidateBlobTarget(c); (err != nil) != fips140.Enabled() {
			t.Fatalf("%s %s: profile=%v err=%v", c.URL, c.S3Endpoint, fips140.Enabled(), err)
		}
	}
	for _, c := range []BlobTarget{
		{URL: "s3://bucket/prefix", AccessKey: "id", Secret: "secret", S3Endpoint: "https://minio.lan:9000"},
		{URL: "sftp://user@host/dir", Secret: "password", HostKey: "SHA256:verified"},
	} {
		if err := ValidateBlobTarget(c); err != nil {
			t.Fatal(err)
		}
	}
}

// test-blob-target probes load through LoadBlobTargetProbe, which skips the production target
// check; the strong profile must still refuse SMB and plain-HTTP S3 there, while an unpinned
// SFTP probe (refused before any authentication) stays allowed.
func TestStrongProfileAppliesToProbes(t *testing.T) {
	probe := func(target string) error {
		path := filepath.Join(t.TempDir(), "config.yaml")
		raw := "data_dir: " + t.TempDir() + "\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\nbackup:\n  blob_target:\n" + target
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadBlobTargetProbe(path)
		return err
	}
	for _, target := range []string{
		"    url: smb://host/share/dir\n    access_key: DOMAIN\\user\n    secret: password\n",
		"    url: s3://bucket/prefix\n    access_key: id\n    secret: secret\n    s3_endpoint: http://minio.lan:9000\n",
	} {
		if err := probe(target); (err != nil) != fips140.Enabled() {
			t.Fatalf("probe %q: profile=%v err=%v", target, fips140.Enabled(), err)
		}
	}
	if err := probe("    url: sftp://fixture@localhost/vault\n    secret: synthetic\n"); err != nil {
		t.Fatalf("unpinned SFTP probe refused: %v", err)
	}
}
