package mirror

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/offsite"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// This is a disposable protocol peer; production transports live in offsite.
func TestPinnedSFTPRecovery(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() == "fixture" && string(password) == "synthetic-password" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				peer, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer peer.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					for request := range requests {
						ok := request.Type == "subsystem" && len(request.Payload) >= 4 && string(request.Payload[4:]) == "sftp"
						_ = request.Reply(ok, nil)
						if ok {
							server, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(dir))
							if err == nil {
								_ = server.Serve()
								_ = server.Close()
							}
							break
						}
					}
					_ = channel.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	cfg := offsite.Config{URL: "sftp://fixture@" + listener.Addr().String() + "/vault", Secret: "synthetic-password", HostKey: ssh.FingerprintSHA256(signer.PublicKey()), Timeout: 3 * time.Second}
	target, err := offsite.Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, blobs, _, _ := fixture(t)
	b := addBlob(t, st, blobs, "sftp", strings.NewReader("opaque note ciphertext over real SSH"))
	if stats, err := Sync(context.Background(), st.DB(), blobs, target, TargetKey(cfg), []Object{b}); err != nil || stats.Uploaded != 1 {
		t.Fatal(stats, err)
	}
	if err = blobs.Delete(b.Digest); err != nil {
		t.Fatal(err)
	}
	if stats, err := Fetch(context.Background(), st.DB(), blobs, target); err != nil || stats.Fetched != 1 {
		t.Fatal(stats, err)
	}
	cfg.HostKey = "SHA256:wrong"
	wrong, err := offsite.Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.Test(context.Background()); err == nil {
		t.Fatal("wrong host key accepted")
	}
}
