package backup

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func postgresRestoreFixture(t *testing.T) *storage.Store {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("native PostgreSQL restore target")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "restore.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`UPDATE orgs SET revision=7`,
		`INSERT INTO orgs(id,status,home_region,revision) VALUES('org_staff','active','local',9)`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t'),('region','local','t'),('cell:local','','t'),('org_poll_revision','100','t'),('erased_poll_revision','100','t'),('replica_config_fingerprint','old','t'),('blob_store_id','retained-store','t'),('blob_probe','old-probe','t'),('backup_interval_sec','900','t'),('kyrecovery_token','sealed-token-to-retain','t')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_restore','restored','hash','salt',600000,'t','t')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('ctr_restore','workbook','usr_restore','t','t')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_restore','ctr_restore','note',1,'t','t')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_restore','usr_restore','token','csrf','t','2099','2099')`,
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_restore','usr_restore','key','device-fingerprint','hash','android','t'),('dev_identity','usr_restore','identity-key','identity-fingerprint','','identity','t')`,
		`INSERT INTO share_links(id,token_hash,object_id,object_version,expires_at,created_at) VALUES('shl_restore','share-token','obj_restore',1,'2099','t')`,
		`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('shl_sealed','sealed-token',X'01','2099','t','usr_restore')`,
		`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES('inv_restore','ctr_restore','usr_restore','usr_restore','invite-token','viewer','t','2099')`,
		`INSERT INTO erased_subjects(subject,org_id,revision) VALUES('already-erased','00000000-0000-0000-0000-000000000001',8)`,
		`INSERT INTO org_pool(org_id,seq,ceiling_bytes,expires_at) VALUES('00000000-0000-0000-0000-000000000001',5,17,'2099')`,
	} {
		if _, err := st.DB().Exec(q); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	if err := storage.PutLogin(t.Context(), st.DB(), "old-pkce", []byte("old-proof"), time.Hour); err != nil {
		t.Fatal(err)
	}
	return st
}
func restoreCount(t *testing.T, st *storage.Store, q string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestPostgresRestorePreparationIsAtomic(t *testing.T) {
	for _, failure := range []string{"none", "schedule", "audit", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			st := postgresRestoreFixture(t)
			if failure == "schedule" || failure == "audit" {
				table, condition := "server_settings", "NEW.key='backup_interval_sec'"
				if failure == "audit" {
					table, condition = "audit_events", "NEW.event='platform.restore_prepared'"
				}
				q := `CREATE FUNCTION deny_restore() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + condition + ` THEN RAISE EXCEPTION 'test restore failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_restore BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION deny_restore()`
				if _, err := st.DB().Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			if failure == "cancel" {
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			err := PreparePostgresRestore(ctx, st)
			if failure != "none" {
				if err == nil {
					t.Fatal("failed safety operation committed")
				}
				for _, q := range []string{
					`SELECT count(*) FROM sessions WHERE revoked_at=''`,
					`SELECT count(*) FROM devices WHERE id='dev_restore' AND revoked_at=''`,
					`SELECT count(*) FROM orgs WHERE id='00000000-0000-0000-0000-000000000001' AND status='active' AND revision=7`,
					`SELECT count(*) FROM org_pool`, `SELECT count(*) FROM replica_logins`, `SELECT count(*) FROM invitations`,
					`SELECT count(*) FROM server_settings WHERE key='backup_interval_sec' AND value='900'`,
					`SELECT count(*) FROM server_settings WHERE key='org_poll_revision' AND value='100'`,
				} {
					if restoreCount(t, st, q) != 1 {
						t.Fatal("failed preparation partially changed target")
					}
				}
				if restoreCount(t, st, `SELECT count(*) FROM audit_events WHERE event='platform.restore_prepared'`) != 0 {
					t.Fatal("failed preparation claimed success")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{
				`SELECT count(*) FROM sessions WHERE revoked_at<>''`,
				`SELECT count(*) FROM devices WHERE id='dev_restore' AND revoked_at<>''`,
				`SELECT count(*) FROM devices WHERE id='dev_identity' AND revoked_at=''`,
				`SELECT count(*) FROM share_links WHERE revoked_at<>''`,
				`SELECT count(*) FROM sealed_share_links WHERE revoked_at<>''`,
				`SELECT count(*) FROM orgs WHERE id='00000000-0000-0000-0000-000000000001' AND status='stale' AND revision=0`,
				`SELECT count(*) FROM orgs WHERE id='org_staff' AND status='active' AND revision=9`,
				`SELECT count(*) FROM erased_subjects WHERE subject='already-erased'`,
				`SELECT count(*) FROM server_settings WHERE key='blob_store_id' AND value='retained-store'`,
				`SELECT count(*) FROM server_settings WHERE key='kyrecovery_token' AND value='sealed-token-to-retain'`,
				`SELECT count(*) FROM audit_events WHERE event='platform.restore_prepared' AND org_id IS NULL`,
			} {
				if restoreCount(t, st, q) != 1 {
					t.Fatalf("restore invariant failed: %s", q)
				}
			}
			for _, q := range []string{`SELECT count(*) FROM invitations`, `SELECT count(*) FROM org_pool`, `SELECT count(*) FROM replica_logins`, `SELECT count(*) FROM server_settings WHERE key IN ('org_poll_revision','erased_poll_revision','replica_config_fingerprint','blob_probe')`} {
				if restoreCount(t, st, q) != 0 {
					t.Fatalf("ephemeral state retained: %s", q)
				}
			}
			if interval, err := recoveryclient.Interval(time.Hour, settings{st}); err != nil || interval != 0 {
				t.Fatalf("schedule not off: %s %v", interval, err)
			}
		})
	}
}
func TestPostgresRestorePreparationRefusesSingleMode(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "single.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	before := restoreCount(t, st, `SELECT count(*) FROM server_settings`)
	if err := PreparePostgresRestore(t.Context(), st); err == nil {
		t.Fatal("single mode accepted native restore reset")
	}
	if restoreCount(t, st, `SELECT count(*) FROM server_settings`) != before {
		t.Fatal("single settings changed")
	}
}
