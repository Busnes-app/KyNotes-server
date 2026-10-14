package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryLockExcludesOtherOwners(t *testing.T) {
	dir := t.TempDir()
	unlock, err := LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := LockDirectory(dir); err == nil {
		other()
		t.Fatal("two directory owners")
	}
	unlock()
	unlock, err = LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

// SIGKILL, OOM and panics leave the file behind; only a live holder may block.
func TestDirectoryLockIgnoresFileLeftByDeadHolder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LockFileName), []byte("999999"), 0600); err != nil {
		t.Fatal(err)
	}
	unlock, err := LockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
