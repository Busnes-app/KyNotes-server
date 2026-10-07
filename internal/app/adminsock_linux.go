//go:build linux

package app

import (
	"net"
	"syscall"
)

// peerAllowed admits the server's uid and root; both already own the container.
func peerAllowed(c *net.UnixConn, uid int) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return false
	}
	return int(cred.Uid) == uid || cred.Uid == 0
}
