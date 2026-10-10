package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func mustFail(t *testing.T, db *sql.DB, want, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: want %q, got %v", q, want, err)
	}
}

func TestAccountKindsHoldTheirInvariants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "kinds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db := st.DB()
	user := `INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,'h','s',1,?,?,'now','now')`
	for _, row := range [][]any{{"usr_admin", "admin", "admin", "admin"}, {"usr_plain", "plain", "user", "user"}, {"usr_inert", "inert", "user", "admin"}} {
		if _, err := db.Exec(user, row...); err != nil {
			t.Fatal(err)
		}
	}
	mustFail(t, db, "CHECK", user, "usr_bad", "bad", "user", "root")
	mustFail(t, db, "admin_role_needs_admin_account", user, "usr_mixed", "mixed", "admin", "user")
	mustFail(t, db, "admin_role_needs_admin_account", `UPDATE users SET role='admin' WHERE id='usr_plain'`)
	mustFail(t, db, "account_kind_fixed", `UPDATE users SET account_kind='admin' WHERE id='usr_plain'`)
	mustFail(t, db, "account_kind_fixed", `UPDATE users SET account_kind='user',role='user' WHERE id='usr_admin'`)
	if _, err := db.Exec(`UPDATE users SET role='user' WHERE id='usr_admin'`); err != nil {
		t.Fatal("revoking the grant must stay possible", err)
	}
	if _, err := db.Exec(`UPDATE users SET role='admin' WHERE id='usr_inert'`); err != nil {
		t.Fatal("granting an admin account must stay possible", err)
	}
	if _, err := db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_plain','workbook','usr_plain','now','now')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"usr_admin", "usr_inert"} {
		mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES(?,'workbook',?,'now','now')`, "cnt_"+id, id)
		mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,'cnt_plain',?,'viewer','now')`, "mem_"+id, id)
		for _, platform := range []string{"identity", "unknown"} {
			mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,'k',?,'h',?,'now')`, "dev_"+id+platform, id, id+platform, platform)
		}
	}
	if _, err := db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_plain','cnt_plain','usr_plain','owner','now')`); err != nil {
		t.Fatal("an everyday member must still be admitted", err)
	}
	if _, err := db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_plain','usr_plain','k','fp','h','unknown','now')`); err != nil {
		t.Fatal(err)
	}
	// A later ownership transfer or re-point must not move content onto an administrator account.
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE containers SET owner_user_id='usr_admin' WHERE id='cnt_plain'`)
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE memberships SET user_id='usr_admin' WHERE id='mem_plain'`)
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE devices SET user_id='usr_admin' WHERE id='dev_plain'`)
	// An identity row belongs to the everyday account that owns its device: never to an admin account.
	ident := `INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES(?,?,x'00','aes-256-gcm','now','now')`
	mustFail(t, db, "admin_account_holds_no_content", ident, "usr_admin", "dev_plain")
	if _, err := db.Exec(ident, "usr_plain", "dev_plain"); err != nil {
		t.Fatal("an everyday identity must still be stored", err)
	}
	mustFail(t, db, "admin_account_holds_no_content", `UPDATE user_identities SET user_id='usr_admin' WHERE user_id='usr_plain'`)
	// Fail closed: an unknown account holds nothing either, even where foreign keys are off (openBefore's raw connection).
	mustFail(t, db, "admin_account_holds_no_content", `INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_ghost','workbook','usr_ghost','now','now')`)
	var approved int
	if err := db.QueryRow(`SELECT approved FROM memberships WHERE id='mem_plain'`).Scan(&approved); err != nil || approved != 1 {
		t.Fatal("memberships default to approved", approved, err)
	}
}

// Migrations before 0026 build a database the way an earlier build left it.
func openBefore(t *testing.T, version int) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		var v int
		if _, err := fmt.Sscanf(f.Name(), "%04d_", &v); err != nil {
			t.Fatal(err)
		}
		if v >= version {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatal(f.Name(), err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES(?,'now')`, v); err != nil {
			t.Fatal(err)
		}
	}
	return db, path
}

func TestMixedAdminsKeepTheirNotesAndDropAdmin(t *testing.T) {
	db, path := openBefore(t, 26)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(q, err)
		}
	}
	for _, u := range [][]string{{"member", "admin"}, {"keyholder", "admin"}, {"owner", "admin"}, {"clean", "admin"}, {"plain", "user"}} {
		exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,'h','s',1,?,'now','now')`, u[0], u[0], u[1])
	}
	exec(`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('team','team','plain',x'01','now','now'),('mine','workbook','owner',x'02','now','now')`)
	exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,revoked_at) VALUES('m1','team','member','editor','now','gone')`)
	exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('idk','keyholder','k','f1','h','identity','now'),('phone','clean','k','f2','h','unknown','now')`)
	exec(`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES('keyholder','idk',x'00','aes-256-gcm','now','now')`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := map[string][2]string{"member": {"user", "user"}, "keyholder": {"user", "user"}, "owner": {"user", "user"}, "clean": {"admin", "admin"}, "plain": {"user", "user"}}
	for id, kr := range want {
		var kind, role string
		if err := st.DB().QueryRow(`SELECT account_kind,role FROM users WHERE id=?`, id).Scan(&kind, &role); err != nil || kind != kr[0] || role != kr[1] {
			t.Fatalf("%s kind=%s role=%s err=%v", id, kind, role, err)
		}
	}
	var meta string
	var rows int
	if err := st.DB().QueryRow(`SELECT hex(meta_ciphertext) FROM containers WHERE id='mine' AND owner_user_id='owner'`).Scan(&meta); err != nil || meta != "02" {
		t.Fatal("a mixed account's notebook changed", meta, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM memberships WHERE id='m1' AND user_id='member'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("a mixed account's membership changed", rows, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM user_identities WHERE user_id='keyholder'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("a mixed account's identity changed", rows, err)
	}
	var revoked, identityRevoked string
	if err := st.DB().QueryRow(`SELECT revoked_at FROM devices WHERE id='phone'`).Scan(&revoked); err != nil || revoked == "" {
		t.Fatal("an admin account kept a device credential", err)
	}
	if err := st.DB().QueryRow(`SELECT revoked_at FROM devices WHERE id='idk'`).Scan(&identityRevoked); err != nil || identityRevoked != "" {
		t.Fatal("an everyday identity was revoked", err)
	}
	reasons := map[string]string{}
	q, err := st.DB().Query(`SELECT object_id,reason_code FROM audit_events WHERE event='account.kind_upgrade'`)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for q.Next() {
		var id, reason string
		if err := q.Scan(&id, &reason); err != nil {
			t.Fatal(err)
		}
		reasons[id] = reason
	}
	for _, id := range []string{"member", "keyholder", "owner"} {
		if reasons[id] != "kind=user,admin_dropped=true" {
			t.Fatalf("%s audit %q", id, reasons[id])
		}
	}
	if reasons["clean"] != "kind=admin" || reasons["plain"] != "" {
		t.Fatalf("audits %v", reasons)
	}
}
