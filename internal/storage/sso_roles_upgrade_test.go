package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestSSOAppRoleUpgradeDoesNotPreserveGlobalAdmin(t *testing.T) {
	for _, withLocal := range []bool{true, false} {
		t.Run(fmt.Sprint(withLocal), func(t *testing.T) {
			names := []string{"linked"}
			if withLocal {
				names = append(names, "local")
			}
			path := filepath.Join(t.TempDir(), "roles-upgrade.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			files, err := migrationFS.ReadDir("migrations")
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				var version int
				if _, err := fmt.Sscanf(f.Name(), "%04d_", &version); err != nil {
					t.Fatal(err)
				}
				if version >= 18 {
					continue
				}
				b, err := migrationFS.ReadFile("migrations/" + f.Name())
				if err != nil {
					t.Fatal(err)
				}
				exec(string(b))
				exec(`INSERT INTO schema_migrations VALUES(?,'now')`, version)
			}
			for _, name := range names {
				sub, issuer := "", ""
				if name == "linked" {
					sub, issuer = "subject", "https://issuer.example"
				}
				exec(`INSERT INTO users(id,username,role,sso_subject,sso_issuer,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?,'admin',?,?,'hash','salt',1,'now','now')`, name, name, sub, issuer)
				exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at,sso_issuer) VALUES(?,?,?,'csrf','now','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z',?)`, name, name, name, issuer)
			}
			exec(`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('kept','workbook','linked',x'010203','now','now')`)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			st, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			db = st.DB()
			for _, name := range names {
				var role, revoked string
				var cap int
				if err := db.QueryRow(`SELECT u.role,s.revoked_at,s.sso_app_admin FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=?`, name).Scan(&role, &revoked, &cap); err != nil {
					t.Fatal(err)
				}
				wantRole := "user"
				if !withLocal {
					wantRole = "admin"
				}
				if name == "linked" && (role != wantRole || revoked == "" || cap != 0) {
					t.Fatalf("linked legacy grant survived %s %s %d", role, revoked, cap)
				}
				if name == "local" && (role != "admin" || revoked != "") {
					t.Fatal("unlinked local admin changed")
				}
			}
			wantReason := "legacy_role=admin"
			if !withLocal {
				wantReason += ",admin_retained=true"
			}
			var body, subject, reason string
			if err := db.QueryRow(`SELECT hex(meta_ciphertext) FROM containers WHERE id='kept'`).Scan(&body); err != nil || body != "010203" {
				t.Fatalf("data changed %s %v", body, err)
			}
			if err := db.QueryRow(`SELECT object_id,reason_code FROM audit_events WHERE event='auth.sso_role_upgrade'`).Scan(&subject, &reason); err != nil || subject != "subject" || reason != wantReason {
				t.Fatalf("upgrade unattributed %q %q %v", subject, reason, err)
			}
			exec(`UPDATE users SET role='admin' WHERE id='linked'`)
			exec(`UPDATE sessions SET revoked_at='',sso_app_admin=1 WHERE id='linked'`)
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var role, revoked string
			if err := st.DB().QueryRow(`SELECT u.role,s.revoked_at FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id='linked'`).Scan(&role, &revoked); err != nil || role != "admin" || revoked != "" {
				t.Fatalf("migration repeated %q %q %v", role, revoked, err)
			}
		})
	}
}
