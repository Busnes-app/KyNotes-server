package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestOfflineCommandsTakeTheDirectoryLock(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	unlock, err := storage.LockDirectory(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"copy-data-dir": func() error {
			return backupCommand([]string{"--out", filepath.Join(t.TempDir(), "copy"), "--config", cfgPath})
		},
		"restore-data-dir": func() error { return restoreCommand([]string{"--in", t.TempDir(), "--force", "--config", cfgPath}) },
		"user add": func() error {
			return userCommand([]string{"add", "--username", "op", "--password", "pw-1", "--config", cfgPath})
		},
		"bootstrap-admin":   func() error { return bootstrapCommand(c) },
		"integrity-check":   func() error { return checkCommand("integrity-check", []string{"--config", cfgPath}) },
		"consistency-check": func() error { return checkCommand("consistency-check", []string{"--config", cfgPath}) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "already in use") {
			t.Errorf("%s ran beside a lock holder: %v", name, err)
		}
	}
}

// A mistyped --retention used to become 0 and delete every unreferenced blob.
func TestGCNowRefusesBadRetention(t *testing.T) {
	cfgPath, _, _ := setupCLIFixture(t)
	for _, r := range []string{"7d", "1x", "-1h"} {
		if err := gcCommand([]string{"--now", "--retention", r, "--config", cfgPath}); err == nil {
			t.Errorf("gc --now --retention %s ran", r)
		}
	}
	// The acceptance probe relies on an explicit 0s.
	if err := gcCommand([]string{"--now", "--retention", "0s", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
}

func TestCopyDataDirRefusesUnsafeOut(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "keep"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dataDir, link); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{full, filepath.Join(dataDir, "copy"), filepath.Join(link, "copy")} {
		if err := backupCommand([]string{"--out", out, "--config", cfgPath}); err == nil {
			t.Errorf("copied into %s", out)
		}
	}
	if b, err := os.ReadFile(filepath.Join(full, "keep")); err != nil || string(b) != "x" {
		t.Fatal("non-empty --out was touched")
	}
}

// restoreFixture returns a target data directory holding old.txt and a plaintext copy
// of another data directory that has one user.
func restoreFixture(t *testing.T) (cfgPath, dataDir, copyDir string) {
	srcCfg, _, _ := setupCLIFixture(t)
	if err := userCommand([]string{"add", "--username", "restored", "--password", "pw-1", "--config", srcCfg}); err != nil {
		t.Fatal(err)
	}
	copyDir = filepath.Join(t.TempDir(), "copy")
	if err := backupCommand([]string{"--out", copyDir, "--config", srcCfg}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(copyDir, storage.LockFileName)); err == nil {
		t.Fatal("copy carried the lock file")
	}
	cfgPath, _, dataDir = setupCLIFixture(t)
	if err := os.WriteFile(filepath.Join(dataDir, "old.txt"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dataDir, copyDir
}

func assertUntouched(t *testing.T, dataDir string) {
	t.Helper()
	if b, err := os.ReadFile(filepath.Join(dataDir, "old.txt")); err != nil || string(b) != "old" {
		t.Fatal("data directory changed:", err)
	}
	staged, _ := filepath.Glob(filepath.Join(dataDir, ".restore-*"))
	if len(staged) != 0 {
		t.Fatal("restore left", staged)
	}
}

func TestRestoreDataDirRefusesBadInputWithoutTouchingData(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	if err := restoreCommand([]string{"--in", copyDir, "--config", cfgPath}); err == nil {
		t.Fatal("replaced a non-empty data directory without --force")
	}
	assertUntouched(t, dataDir)
	if err := restoreCommand([]string{"--in", filepath.Join(t.TempDir(), "typo"), "--force", "--config", cfgPath}); err == nil {
		t.Fatal("restored a missing --in")
	}
	assertUntouched(t, dataDir)
	nested := filepath.Join(copyDir, "nested")
	nestedCfg := filepath.Join(t.TempDir(), "kynotes.yaml")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestedCfg, []byte("data_dir: "+nested+"\nserver:\n  bind: 127.0.0.1:0\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", nestedCfg}); err == nil || !strings.Contains(err.Error(), "inside --in") {
		t.Fatal("restored from a parent of the data directory:", err)
	}
	if err := os.RemoveAll(nested); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, "kynotes.sqlite"), []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", cfgPath}); err == nil {
		t.Fatal("restored a corrupt database")
	}
	assertUntouched(t, dataDir)
}

func TestRestoreDataDirRefusesCopyWithoutSecrets(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	if err := os.RemoveAll(filepath.Join(copyDir, "secrets")); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", cfgPath}); err == nil {
		t.Fatal("restored without secrets; the server would mint new ones")
	}
	assertUntouched(t, dataDir)
}

func TestRestoreDataDirSwapsAndKeepsPrevious(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "old.txt")); err == nil {
		t.Fatal("old entry still in place")
	}
	previous, _ := filepath.Glob(filepath.Join(dataDir, ".restore-previous-*", "old.txt"))
	if len(previous) != 1 {
		t.Fatal("previous data not kept")
	}
	if staged, _ := filepath.Glob(filepath.Join(dataDir, ".restore-staging-*")); len(staged) != 0 {
		t.Fatal("staging left behind")
	}
	s, err := storage.Open(filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err = s.DB().QueryRow(`SELECT count(*) FROM users WHERE username='restored'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("restored database missing its user", n, err)
	}
}
