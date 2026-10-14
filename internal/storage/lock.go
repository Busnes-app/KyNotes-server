package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// LockFileName is never copied or replaced: the kernel lock lives on its inode.
const LockFileName = ".kynotes.lock"

// LockDirectory gives server and offline recovery commands the same exclusive owner.
// The kernel drops the lock when the holder exits, however it exits; the file stays.
func LockDirectory(dir string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(dir, LockFileName), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("data directory is inaccessible: %w", err)
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("data directory is already in use: %w", err)
	}
	// The PID is for operators only.
	if err = file.Truncate(0); err == nil {
		_, err = file.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = file.Close() }, nil
}
