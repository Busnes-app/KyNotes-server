package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// A killed Collect's snapshot-* copy is removed at the next start; nothing else is touched.
func TestSweepSnapshotsRemovesOnlyStaleCopies(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"snapshot-123/kynotes.sqlite", "blobs/ab", "kynotes.sqlite"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	SweepSnapshots(dir)
	if _, err := os.Stat(filepath.Join(dir, "snapshot-123")); !os.IsNotExist(err) {
		t.Fatal("stale snapshot kept:", err)
	}
	for _, name := range []string{"blobs/ab", "kynotes.sqlite"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal("swept", name, err)
		}
	}
}
