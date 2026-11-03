package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// Restoring into a fresh, empty volume needs no --force: loading the config must not
// create secrets/ there first.
func TestRestoreDataDirIntoAnEmptyVolume(t *testing.T) {
	_, _, copyDir := restoreFixture(t)
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	cfgPath := filepath.Join(root, "kynotes.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "kynotes.sqlite")); err != nil {
		t.Fatal("restored database missing:", err)
	}
}

// A copy made with a newer binary must keep the schema of the data it copies.
func TestCopyDataDirDoesNotMigrate(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO schema_migrations VALUES(1,'old')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	out := filepath.Join(t.TempDir(), "copy")
	if err := backupCommand([]string{"--out", out, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	copied, err := sql.Open("sqlite", filepath.Join(out, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	var n int
	if err := copied.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("copy schema version=%d %v, want 1 (unmigrated)", n, err)
	}
}

// On a terminal, user add without --password says what it needs instead of waiting forever.
func TestUserAddWithoutPasswordOnATerminalFailsFast(t *testing.T) {
	tty, err := os.Open("/dev/null")
	if err != nil {
		t.Skip(err)
	}
	defer tty.Close()
	if st, _ := tty.Stat(); st.Mode()&os.ModeCharDevice == 0 {
		t.Skip("/dev/null is not a character device here")
	}
	cfgPath, _, _ := setupCLIFixture(t)
	stdin := os.Stdin
	os.Stdin = tty
	defer func() { os.Stdin = stdin }()
	err = userCommand([]string{"add", "--username", "op", "--admin", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "--password") {
		t.Fatalf("err=%v, want a hint to pass --password", err)
	}
}
