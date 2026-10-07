//go:build !linux

package app

import "net"

// ponytail: peer credentials are read only on Linux, the shipped platform; elsewhere the
// socket refuses every peer. Upgrade path: getpeereid via golang.org/x/sys/unix.
func peerAllowed(*net.UnixConn, int) bool { return false }
