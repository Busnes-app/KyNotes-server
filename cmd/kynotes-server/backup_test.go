package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/Busnes-app/ky-primitives/offsite"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/mirror"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestRestoreCapsuleWithStdinSharesPreservesLoginAndRevokesSessions(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	secret := strings.Repeat("a", 64)
	hash, err := auth.HashAuthSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,created_at,updated_at) VALUES('usr_fixture','admin',?,'salt',600000,'admin','active','','')`, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('sess_fixture','usr_fixture','token','csrf',?,?,?)`, time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cfg.Backup.BlobTarget.URL = "file://" + t.TempDir()
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for i, content := range []string{"synthetic encrypted note version", "synthetic encrypted attachment"} {
		temp, err := blobs.NewTemp([]string{"note", "attachment"}[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(temp, content); err != nil {
			t.Fatal(err)
		}
		digest, size, err := temp.Finalize("")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = st.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,'')`, digest, size); err != nil {
			t.Fatal(err)
		}
		contents[digest] = content
	}
	svc := backup.New(cfg, st, "test")
	defer svc.Close()
	if stats, err := svc.MirrorNow(context.Background(), "system", "fixture"); err != nil || stats.Uploaded != 2 {
		t.Fatal(stats, err)
	}
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Pin("system", "fixture", base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	raw, _, err := svc.Export(context.Background(), "system", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.kycap")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(key, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	input := shares[0].String() + "\n" + shares[2].String() + "\n"
	parent, err := os.MkdirTemp(".", ".restore-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	parent, err = filepath.Abs(parent)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "restored")
	var output bytes.Buffer
	if err = restoreCapsule(path, target, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), shares[0].String()) || strings.Contains(output.String(), cfg.Secrets.ServerSaltKey) {
		t.Fatal("restore printed secrets")
	}
	got, err := config.Load(filepath.Join(target, "kynotes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DataDir != target || got.Secrets != cfg.Secrets {
		t.Fatal("restore changed secrets or directory")
	}
	restored, err := storage.Open(filepath.Join(target, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	recoveredBlobs, err := blobstore.New(target)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := offsite.Parse(got.Backup.BlobTarget.Offsite())
	if err != nil {
		t.Fatal(err)
	}
	if stats, err := mirror.Fetch(context.Background(), restored.DB(), recoveredBlobs, remote); err != nil || stats.Fetched != 2 {
		t.Fatal(stats, err)
	}
	for digest, want := range contents {
		f, _, err := recoveredBlobs.Open(digest)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(raw) != want {
			t.Fatal("restored ciphertext differs")
		}
	}
	var verifier, revoked string
	if err = restored.DB().QueryRow(`SELECT auth_secret_hash FROM users WHERE id='usr_fixture'`).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	if err = auth.VerifyAuthSecret(secret, verifier); err != nil {
		t.Fatal("restored login failed")
	}
	if err = restored.DB().QueryRow(`SELECT revoked_at FROM sessions WHERE id='sess_fixture'`).Scan(&revoked); err != nil || revoked == "" {
		t.Fatal("old session resurrected")
	}
	if err = restoreCapsule(path, target, strings.NewReader(input), &output); err == nil {
		t.Fatal("overwrote occupied target")
	}
	if err = restoreCapsule(path, filepath.Join(t.TempDir(), "bad"), strings.NewReader(shares[0].String()), &output); err == nil {
		t.Fatal("accepted insufficient shares")
	}
	bad := append([]byte{}, raw...)
	bad[len(bad)/2] ^= 1
	if err = os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err = restoreCapsule(path, filepath.Join(t.TempDir(), "tampered"), strings.NewReader(input), &output); err == nil {
		t.Fatal("accepted tampered capsule")
	}
	wrong, _, err := recoveryclient.Seal(recoveryclient.Payload{ServiceName: "Other", AppVersion: "test", Files: []recoveryclient.File{{Path: "file", Data: []byte("x"), Mode: 0600}}}, recoveryclient.RecoveryKey{Public: key.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, wrong, 0600); err != nil {
		t.Fatal(err)
	}
	if err = restoreCapsule(path, filepath.Join(t.TempDir(), "foreign"), strings.NewReader(input), &output); err == nil {
		t.Fatal("foreign service accepted")
	}
}
