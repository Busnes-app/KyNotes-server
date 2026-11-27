package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

func TestLoadOrCreateDeviceKeyUpgradesLegacyX25519Key(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.key")

	legacy, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate legacy key: %v", err)
	}
	if err := os.WriteFile(path, legacy.Bytes(), 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	upgraded, err := loadOrCreateDeviceKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateDeviceKey(legacy): %v", err)
	}
	if got := len(upgraded.Bytes()); got != teamkeys.PQPrivateBytes {
		t.Fatalf("upgraded key length = %d, want %d", got, teamkeys.PQPrivateBytes)
	}
	if got := len(upgraded.PublicKey().Bytes()); got != teamkeys.PQPublicBytes {
		t.Fatalf("upgraded public key length = %d, want %d", got, teamkeys.PQPublicBytes)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat upgraded key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("upgraded key mode = %o, want 600", info.Mode().Perm())
	}

	// Second load must return the exact persisted PQ key without regenerating it.
	reloaded, err := loadOrCreateDeviceKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateDeviceKey: %v", err)
	}
	if !bytes.Equal(reloaded.Bytes(), upgraded.Bytes()) {
		t.Fatal("reloaded key differs from persisted upgraded key")
	}

	// Upgraded key must work as a PQ envelope recipient.
	sender, err := teamkeys.NewIdentity()
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	wantKey := bytes.Repeat([]byte{0x2a}, 32)
	const (
		orgID       = "org_test"
		containerID = "cnt_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		probeDevID  = "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		senderDevID = "dev_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	sealed, err := teamkeys.SealPQEnvelope(wantKey, reloaded.PublicKey().Bytes(), orgID, containerID, 2, probeDevID, sender.Bytes(), senderDevID)
	if err != nil {
		t.Fatalf("SealPQEnvelope to upgraded probe key: %v", err)
	}
	opened, err := teamkeys.OpenIdentityEnvelope(teamkeys.PQEnvelopeAlg, sealed, reloaded.Bytes(), orgID, containerID, 2, probeDevID, sender.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("OpenIdentityEnvelope with upgraded probe key: %v", err)
	}
	if !bytes.Equal(opened, wantKey) {
		t.Fatal("opened content key mismatch")
	}
}
