package applysetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagePublishesPrivateBundleAndPreservesIntent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "installer", "setup.json")
	raw := []byte(`{"version":1,"backup":{"dir":"/backups","keep":7,"depositInterval":"24h"}}`)
	if _, err := Stage(dir, file, raw, false, true); err == nil {
		t.Fatal("missing bundle inspected as present")
	}
	if _, err := os.Stat(filepath.Dir(file)); !os.IsNotExist(err) {
		t.Fatal("inspection created a directory")
	}
	status, err := Stage(dir, file, raw, false, false)
	if err != nil || status != "created" {
		t.Fatal(status, err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(file)
	if st.Mode().Perm() != 0600 {
		t.Fatal("shared prepared file", st.Mode())
	}
	for _, check := range []bool{true, false} {
		status, err = Stage(dir, file, raw, false, check)
		if err != nil || status != "present" {
			t.Fatal("resume", status, err)
		}
		changed := []byte(strings.Replace(string(raw), `"keep":7`, `"keep":8`, 1))
		if _, err := Stage(dir, file, changed, false, check); err == nil {
			t.Fatal("changed intent overwritten")
		}
	}
	after, _ := os.ReadFile(file)
	if string(after) != string(before) {
		t.Fatal("existing bundle changed")
	}
	if _, err := Load(file, false); err != nil {
		t.Fatal("prepared native bundle invalid", err)
	}
}

func TestStageRefusesInvalidMetadataBeforeWriting(t *testing.T) {
	for _, raw := range []string{
		`{"version":2}`, `{"version":1} {}`, `{"version":1,"clientSecret":"must-not-echo"}`,
		`{"version":1,"sso":{"issuerUrl":"http://id.example","clientId":"notes","clientSecretFile":"/secrets/client","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}`,
		`{"version":1,"backup":{"recovery":{"url":"https://recovery.example","pairingCodeFile":"relative"}}}`,
		strings.Repeat("x", MaxBundleBytes+1),
	} {
		dir := t.TempDir()
		_, err := Stage(dir, filepath.Join(dir, "installer", "setup.json"), []byte(raw), false, false)
		if err == nil || strings.Contains(err.Error(), "must-not-echo") {
			t.Fatal("invalid preparation accepted/disclosed", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "installer")); !os.IsNotExist(err) {
			t.Fatal("invalid metadata wrote a directory")
		}
	}
	dir := t.TempDir()
	if _, err := Stage(dir, filepath.Join(dir, "foreign.json"), []byte(`{"version":1}`), false, false); err == nil {
		t.Fatal("arbitrary target file allowed")
	}
}

func TestStageRefusesSharedAndLinkedStorage(t *testing.T) {
	for _, kind := range []string{"shared", "link", "existing-shared-file"} {
		t.Run(kind, func(t *testing.T) {
			dir, foreign := t.TempDir(), t.TempDir()
			installer := filepath.Join(dir, "installer")
			if kind == "link" {
				if err := os.Symlink(foreign, installer); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(installer, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "shared" {
					if err := os.Chmod(installer, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "existing-shared-file" {
					f := filepath.Join(installer, "setup.json")
					if err := os.WriteFile(f, []byte("keep-foreign-data"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(f, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := Stage(dir, filepath.Join(installer, "setup.json"), []byte(`{"version":1}`), false, false); err == nil {
				t.Fatal("unsafe storage accepted")
			}
			entries, _ := os.ReadDir(foreign)
			if len(entries) != 0 {
				t.Fatal("symlink destination mutated")
			}
		})
	}
}
