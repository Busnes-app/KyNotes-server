package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// pg-backup and pg-restore take no DSN or key in argv, refuse every other flag shape before
// any database or file work, and accept only a regular file of 64 hex characters as the key.
func TestPostgresArchiveCommandRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", key)
	t.Setenv("KYNOTES_DB_DSN", "")
	for _, c := range []struct {
		name, want string
		args       []string
	}{
		{"pg-backup", "usage", nil},
		{"pg-backup", "usage", []string{"--out", "x", "--confirm-stopped"}},
		{"pg-backup", "usage", []string{"--out", "x", "postgres://u:p@h/db"}},
		{"pg-restore", "usage", []string{"--in", "x"}},
		{"pg-restore", "usage", []string{"--in", "x", "--out", "y", "--confirm-stopped"}},
		{"pg-restore", "usage", []string{"--dsn", "postgres://u:p@h/db", "--in", "x", "--confirm-stopped"}},
		{"pg-backup", "KYNOTES_DB_DSN", []string{"--out", filepath.Join(dir, "a.pgb")}},
		{"pg-restore", "KYNOTES_DB_DSN", []string{"--in", "x", "--confirm-stopped"}},
	} {
		err := postgresArchiveCommand(c.name, c.args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "u:p@") {
			t.Errorf("%s %v: %v", c.name, c.args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "a.pgb")); !os.IsNotExist(err) {
		t.Fatal("a refused backup created its file")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"short": strings.Repeat("ab", 31), "long": strings.Repeat("ab", 33), "not hex": strings.Repeat("zz", 32), "two lines": strings.Repeat("ab", 32) + "\n\n"} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", path)
		if _, err := readBackupKey(); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	for _, path := range []string{"", dir, fifo, filepath.Join(dir, "missing")} {
		t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", path)
		if _, err := readBackupKey(); err == nil {
			t.Errorf("key file %q accepted", path)
		}
	}
	t.Setenv("KYNOTES_PG_BACKUP_KEY_FILE", key)
	if k, err := readBackupKey(); err != nil || len(k) != 32 || k[0] != 0xab {
		t.Fatalf("valid key: %v", err)
	}
}
