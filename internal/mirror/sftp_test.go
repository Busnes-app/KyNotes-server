package mirror

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	pinnedSFTPRecovery(t, signer, false, false)
}

func TestSFTPTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bits    int
		sha1KEX bool
		refuse  bool
	}{
		{"RSA1024", 1024, false, true},
		{"RSA2047", 2047, false, true},
		{"RSA2048", 2048, false, false},
		{"SHA1KEX", 2048, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private, err := rsa.GenerateKey(rand.Reader, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			pinnedSFTPRecovery(t, signer, tc.sha1KEX, tc.refuse)
		})
	}
}

func pinnedSFTPRecovery(t *testing.T, signer ssh.Signer, sha1KEX, refuse bool) {
	t.Helper()
	var authenticated atomic.Int64
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authenticated.Add(1)
		if meta.User() == "fixture" && string(password) == "synthetic-password" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	if sha1KEX {
		serverConfig.KeyExchanges = []string{"diffie-hellman-group14-sha1"}
	}
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
	if err = target.Test(context.Background()); (err != nil) != refuse {
		t.Fatalf("probe error = %v, want refusal %v", err, refuse)
	}
	st, blobs, _, _ := fixture(t)
	b := addBlob(t, st, blobs, "sftp", strings.NewReader("opaque note ciphertext over real SSH"))
	if refuse {
		stats, err := Sync(context.Background(), st.DB(), blobs, target, TargetKey(cfg), []Object{b})
		if err == nil || stats.Failed != 1 || stats.Uploaded != 0 {
			t.Fatalf("weak transport acknowledged: %+v, %v", stats, err)
		}
		pending, err := Pending(st.DB(), TargetKey(cfg))
		if err != nil || pending != 1 {
			t.Fatalf("failed mirror lost pending blob: %d, %v", pending, err)
		}
		if authenticated.Load() != 0 {
			t.Fatal("weak transport reached password authentication")
		}
		return
	}
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
