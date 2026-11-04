package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// A symlinked --in (for example backups/latest) restores its data, not a fresh empty database.
func TestRestoreDataDirFollowsASymlinkedCopy(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	link := filepath.Join(t.TempDir(), "latest")
	if err := os.Symlink(copyDir, link); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", link, "--force", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM users WHERE username='restored'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("restored database is not the copy", n, err)
	}
}

// A link inside the copy is refused rather than dropped from it.
func TestRestoreDataDirRefusesALinkInsideTheCopy(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	if err := os.Symlink("/nonexistent", filepath.Join(copyDir, "blobs-link")); err != nil {
		t.Fatal(err)
	}
	if err := restoreCommand([]string{"--in", copyDir, "--force", "--config", cfgPath}); err == nil {
		t.Fatal("a link in the copy was dropped silently")
	}
	assertUntouched(t, dataDir)
}

// A mistyped flag is refused instead of restoring without it.
func TestRestoreDataDirRefusesUnknownFlags(t *testing.T) {
	cfgPath, dataDir, copyDir := restoreFixture(t)
	err := restoreCommand([]string{"--in", copyDir, "--force", "--revoke-credential", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "--revoke-credential") {
		t.Fatal("unknown flag accepted:", err)
	}
	assertUntouched(t, dataDir)
}

// A previous restore's leftovers are not copied again.
func TestCopyDataDirSkipsRestoreLeftovers(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	if err := os.MkdirAll(filepath.Join(dataDir, ".restore-previous-1", "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ".restore-previous-1", "blobs", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A killed drill's scratch holds a decrypted database and secrets (pass 4).
	if err := os.MkdirAll(filepath.Join(dataDir, "recoveryclient-drill-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy")
	if err := backupCommand([]string{"--out", out, "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, ".restore-previous-1")); err == nil {
		t.Fatal("restore leftovers copied")
	}
	if _, err := os.Stat(filepath.Join(out, "recoveryclient-drill-1")); err == nil {
		t.Fatal("drill scratch copied")
	}
	if _, err := os.Stat(filepath.Join(out, "kynotes.sqlite")); err != nil {
		t.Fatal("database not copied:", err)
	}
}

// gc beside a live server never migrates a database an older release wrote.
func TestGCRefusesAnOlderSchema(t *testing.T) {
	cfgPath, _, dataDir := setupCLIFixture(t)
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO schema_migrations VALUES(1,'old')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := gcCommand([]string{"--now", "--config", cfgPath}); err == nil {
		t.Fatal("gc ran against an older schema")
	}
	db, err = sql.Open("sqlite", filepath.Join(dataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err = db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("gc migrated the database: version %d %v", n, err)
	}
}
