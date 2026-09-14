package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestSSOUpgradeRevokesOnlyUntraceableCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Construct the actual pre-feature schema, not a hand-written approximation.
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		var version int
		if _, err := fmt.Sscanf(f.Name(), "%04d_", &version); err != nil {
			t.Fatal(err)
		}
		if version >= 16 {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		mustExec(string(b))
		mustExec(`INSERT INTO schema_migrations VALUES(?,'now')`, version)
	}
	mustExec(`INSERT INTO server_settings VALUES('sso_issuer_url','https://issuer.example','now')`)
	for _, name := range []string{"linked", "local"} {
		subject := ""
		if name == "linked" {
			subject = "subject"
		}
		mustExec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,sso_subject) VALUES(?,?,'hash','salt',1,'now','now',?)`, name, name, subject)
		mustExec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES(?,?,?,'csrf','now','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`, name, name, name)
		mustExec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,created_at) VALUES(?,?,'pub',?,'secret','now')`, name, name, name)
	}
	mustExec(`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('container','workbook','linked',x'010203','now','now')`)
	mustExec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('key','container','linked',1,'fixture',x'040506','now')`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db = st.DB()
	for _, table := range []string{"sessions", "devices"} {
		for _, name := range []string{"linked", "local"} {
			var revoked string
			if err := db.QueryRow(`SELECT revoked_at FROM `+table+` WHERE id=?`, name).Scan(&revoked); err != nil {
				t.Fatal(err)
			}
			if (revoked != "") != (name == "linked") {
				t.Fatalf("%s %s revocation=%q", table, name, revoked)
			}
		}
	}
	var issuer, ciphertext, envelope string
	if err := db.QueryRow(`SELECT sso_issuer FROM users WHERE id='linked'`).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	if issuer != "https://issuer.example" {
		t.Fatalf("issuer=%q", issuer)
	}
	if err := db.QueryRow(`SELECT hex(meta_ciphertext) FROM containers WHERE id='container'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT hex(envelope) FROM key_envelopes WHERE id='key'`).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	if ciphertext != "010203" || envelope != "040506" {
		t.Fatal("upgrade changed encrypted data")
	}
	var audits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_upgrade'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("upgrade audit: %d %v", audits, err)
	}
	// A later startup must not revoke newly established SSO credentials.
	mustExec(`UPDATE sessions SET revoked_at='',sso_issuer=?,sso_subject='subject',sso_sid='new' WHERE id='linked'`, issuer)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var revoked string
	if err := st.DB().QueryRow(`SELECT revoked_at FROM sessions WHERE id='linked'`).Scan(&revoked); err != nil || revoked != "" {
		t.Fatalf("reopen revoked new session: %q %v", revoked, err)
	}
}
