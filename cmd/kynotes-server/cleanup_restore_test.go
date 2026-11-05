package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// The old representation fits a real capsule, but 250000 ordinary1024-byte
// cleanup slots alone exceed the unchanged90% budget. This is an authentic
// custodian-opened legacy capsule, not a lowered test-only budget.
func TestCapacityRefusedRestoreStillRevokesCredentialsAndStopsDeposits(t *testing.T) {
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	cfg.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Retain the actual schema30 tables and contents, removing only unpublished0031.
	for _, q := range []string{`DROP VIEW audit_history`, `DROP TRIGGER cleanup_comment_pending`, `DROP TRIGGER cleanup_link_pending`, `DROP TABLE cleanup_audit_slots`, `ALTER TABLE comments DROP COLUMN cleanup_padding`, `ALTER TABLE containers DROP COLUMN cleanup_padding`, `ALTER TABLE sealed_share_links DROP COLUMN cleanup_padding`, `DELETE FROM schema_migrations WHERE version=31`} {
		if _, err = st.DB().Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,created_at,updated_at) VALUES('admin','admin','opaque','salt',600000,'admin','admin','active','now','now'),('person','person','opaque','salt',600000,'user','user','active','now','now')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('session','person','token','csrf','now',?1,?1)`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('notebook','workbook','person','now','now')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('page','notebook','note',1,'now','now')`,
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('paired','person','pk','fp','secret','web','now'),('identity','person','pk2','fp2','!','identity','now')`,
		`INSERT INTO share_links(id,token_hash,object_id,object_version,expires_at,created_at) VALUES('object-link','object-token','page',1,?1,'now')`,
		`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('sealed-link','sealed-token',X'63',?1,'now','person')`,
		`INSERT INTO invitations(id,container_id,inviter_id,token_hash,role,created_at,expires_at) VALUES('invitation','notebook','person','invitation-token','viewer','now',?1)`,
		`WITH RECURSIVE sequence(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM sequence WHERE i<250000) INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) SELECT printf('cmt_%026d',i),'notebook','page','person',X'63',1,i,'2026-11-05T00:00:00Z' FROM sequence`,
	} {
		if _, err = st.DB().Exec(q, later); err != nil {
			t.Fatal(q, err)
		}
	}
	if err = st.SetSetting("backup_interval_sec", "900"); err != nil {
		t.Fatal(err)
	}
	svc := backup.New(cfg, st, "legacy-test")
	defer svc.Close()
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
	path := filepath.Join(t.TempDir(), "legacy.kycap")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(key, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "restored")
	var output bytes.Buffer
	err = restoreCapsule(path, target, strings.NewReader(shares[0].String()+"\n"+shares[1].String()+"\n"), &output)
	if !errors.Is(err, storage.ErrCleanupCapacity) || !strings.Contains(err.Error(), "revoked") || !strings.Contains(err.Error(), "old release") {
		t.Fatalf("expected capacity refusal, got%v", err)
	}
	restored, err := storage.OpenUnmigrated(filepath.Join(target, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	for _, q := range []string{`SELECT count(*) FROM sessions WHERE revoked_at=''`, `SELECT count(*) FROM devices WHERE revoked_at='' AND platform<>'identity'`, `SELECT count(*) FROM share_links WHERE revoked_at=''`, `SELECT count(*) FROM sealed_share_links WHERE revoked_at=''`, `SELECT count(*) FROM invitations WHERE status='pending'`} {
		var n int
		if err = restored.DB().QueryRow(q).Scan(&n); err != nil || n != 0 {
			t.Errorf("restored credentials remain live: %s =%d %v", q, n, err)
		}
	}
	var version, comments, identities int
	if err = restored.DB().QueryRow(`SELECT (SELECT max(version) FROM schema_migrations),(SELECT count(*) FROM comments),(SELECT count(*) FROM devices WHERE platform='identity' AND revoked_at='')`).Scan(&version, &comments, &identities); err != nil || version != 30 || comments != 250000 || identities != 1 {
		t.Errorf("legacy content/identity changed %d/%d/%d %v", version, comments, identities, err)
	}
	if interval, err := restored.GetSetting("backup_interval_sec"); err != nil || interval != "0" {
		t.Errorf("restored deposits enabled: %s %v", interval, err)
	}
	var originalLive int
	if err = st.DB().QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at=''`).Scan(&originalLive); err != nil || originalLive != 1 {
		t.Errorf("original credentials changed%d %v", originalLive, err)
	}
	if interval, err := st.GetSetting("backup_interval_sec"); err != nil || interval != "900" {
		t.Errorf("original schedule changed%s %v", interval, err)
	}
}
