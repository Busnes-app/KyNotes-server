package app

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

// AdminSocketPath is where apply-setup reaches the running server.
func AdminSocketPath(dataDir string) string { return filepath.Join(dataDir, "admin.sock") }

// listenAdminSocket binds the local admin socket at mode 0600. The caller holds the
// data-directory lock, so a socket already at the path is a crash leftover; any other
// file type is refused.
func listenAdminSocket(dataDir string) (net.Listener, error) {
	path := AdminSocketPath(dataDir)
	if st, err := os.Lstat(path); err == nil {
		if st.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("admin socket: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return peerListener{Listener: l, uid: os.Getuid()}, nil
}

// peerListener closes connections from any uid but the server's own and root.
type peerListener struct {
	net.Listener
	uid int
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uc, ok := c.(*net.UnixConn); ok && peerAllowed(uc, l.uid) {
			return c, nil
		}
		c.Close()
	}
}
