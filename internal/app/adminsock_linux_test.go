//go:build linux

package app

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPeerAllowedRefusesOtherUIDs(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always admitted")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "p.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !peerAllowed(server, os.Getuid()) {
		t.Fatal("own uid refused")
	}
	if peerAllowed(server, os.Getuid()+1) {
		t.Fatal("other uid admitted")
	}
}

func TestAdminSocketPrivateUnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	l, err := listenAdminSocket(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, err := os.Lstat(AdminSocketPath(dir))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", st.Mode(), err)
	}
}

func TestPeerListenerDropsRefusedPeers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always admitted")
	}
	inner, err := net.Listen("unix", filepath.Join(t.TempDir(), "p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	l := peerListener{Listener: inner, uid: os.Getuid() + 1}
	accepted := make(chan error, 1)
	go func() { _, err := l.Accept(); accepted <- err }()
	client, err := net.Dial("unix", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused peer read data")
	}
	l.Close()
	if err := <-accepted; err == nil {
		t.Fatal("refused peer was accepted")
	}
}
