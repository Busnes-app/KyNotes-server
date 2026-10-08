package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGCDeletesEnvelopesOfExpiredInvitations(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now'),('usr_b','b','h','s',100000,'now','now')`)
	exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_t','team','usr_a','now','now')`)
	exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_b','usr_b','pk','fp','x','identity','now')`)
	for id, expires := range map[string]string{"inv_old": stamp(-time.Minute), "inv_live": stamp(time.Hour)} {
		exec(`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES(?,'cnt_t','usr_a','usr_b',?,'editor','now',?)`, id, "hash-"+id, expires)
		exec(`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES(?,'cnt_t','dev_b',1,'x25519-hkdf-sha256-chacha20poly1305',x'01')`, id)
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := db.Query(`SELECT invitation_id FROM invitation_envelopes`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "inv_live" {
		t.Fatalf("envelopes left=%v, want only inv_live", left)
	}
	var invitations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invitations`).Scan(&invitations); err != nil || invitations != 2 {
		t.Fatalf("GC deleted invitation rows: %d %v", invitations, err)
	}
}

func TestGCDeletesExpiredLinkRequests(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','t','c','now','` + stamp(time.Hour) + `','` + stamp(time.Hour) + `')`,
		`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES('lnk_old','usr_a','ses_a',zeroblob(32),'now','` + stamp(-time.Minute) + `'),('lnk_live','usr_a','ses_a',zeroblob(32),'now','` + stamp(time.Minute) + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left string
	if err := db.QueryRow(`SELECT group_concat(id) FROM link_requests`).Scan(&left); err != nil || left != "lnk_live" {
		t.Fatalf("left=%q %v, want lnk_live", left, err)
	}
}
