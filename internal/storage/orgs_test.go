package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Every table, by tenancy class (spec "Inventory"). A new table fails TestEveryTableIsClassified
// until it is listed here.
var (
	orgOwned = map[string]string{ // table -> the parent its org must equal ("" for none)
		"org_usage": "", "users": "", "containers": "users", "blobs": "", "blob_containers": "containers",
		"object_versions": "objects", "conflicts": "containers", "attachments": "containers",
		"upload_sessions": "containers", "audit_events": "", "sealed_share_links": "users",
	}
	derived = map[string]string{ // table -> the parent it is scoped through
		"sessions": "users", "objects": "containers", "devices": "users", "memberships": "containers",
		"key_envelopes": "containers", "device_containers": "containers", "invitations": "containers",
		"comments": "containers", "mentions": "comments", "activity": "containers",
		"push_registrations": "devices", "attachment_refs": "attachments", "share_links": "objects",
		"sso_stepup": "sessions", "user_identities": "users", "invitation_envelopes": "invitations",
		"link_requests": "users", "reminders": "users", "web_push_subscriptions": "users",
		"cleanup_audit_slots": "comments",
	}
	platform = map[string]bool{
		"schema_migrations": true, "pairing_nonces": true, "idempotency": true, "idempotency_keys": true,
		"server_settings": true, "sso_sync_events": true, "sso_logout_events": true,
		"sso_directory_state": true, "sso_login_cutoffs": true, "orgs": true, "erased_subjects": true,
		"org_pool": true,
	}
	offInMulti = map[string]bool{"blob_replicas": true}
	// Tables the PostgreSQL schema leaves out (tenancy spec, Replica work, item 6).
	sqliteOmits   = map[string]bool{"org_usage": true}
	postgresOmits = map[string]bool{"cleanup_audit_slots": true, "blob_replicas": true}
)

func openFresh(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEveryTableIsClassified(t *testing.T) {
	s := openFresh(t)
	seen := map[string]bool{}
	for _, name := range catalogTables(t, s) {
		seen[name] = true
		_, o := orgOwned[name]
		_, d := derived[name]
		n := 0
		for _, in := range []bool{o, d, platform[name], offInMulti[name]} {
			if in {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s is in %d tenancy classes, want exactly 1", name, n)
		}
	}
	for _, m := range []map[string]string{orgOwned, derived} {
		for name := range m {
			if !seen[name] && !(s.pg && postgresOmits[name]) && !(!s.pg && sqliteOmits[name]) {
				t.Errorf("%s is classified but does not exist", name)
			}
		}
	}
}

func TestOrgOwnedTablesHaveOrgID(t *testing.T) {
	s := openFresh(t)
	for table, parent := range orgOwned {
		if !s.pg && sqliteOmits[table] {
			continue
		}
		notNull, def, err := catalogColumn(s, table, "org_id")
		if err != nil {
			t.Errorf("%s: no org_id: %v", table, err)
			continue
		}
		if table == "audit_events" {
			if notNull || def != "" {
				t.Errorf("audit_events.org_id must be nullable with no default")
			}
		} else if !notNull || def != "'"+DefaultOrgID+"'" {
			t.Errorf("%s.org_id: notnull=%v default=%q", table, notNull, def)
		}
		want := []string{table + "_org_exists", table + "_org_fixed"}
		if parent != "" {
			want = append(want, table+"_org_parent", table+"_org_parent_move")
		}
		for _, trigger := range want {
			if !catalogTrigger(s, trigger, table) {
				t.Errorf("%s: trigger %s missing", table, trigger)
			}
		}
	}
}

// legacyOrgDatabase is a schema-0031 install, as the release before tenancy left it, with one
// row in each org-owned table that matters to the upgrade.
func legacyOrgDatabase(t *testing.T, path string) {
	t.Helper()
	s, err := open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	files, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range files[:cleanupSchemaVersion] {
		b, _ := migrationFS.ReadFile("migrations/" + f.Name())
		if _, err = s.db.Exec(string(b)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec(`INSERT INTO schema_migrations VALUES(?,'2026-01-01T00:00:00Z')`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_00000000000000000000000000','u','x','x',100000,'t','t')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_00000000000000000000000000','workbook','usr_00000000000000000000000000','t','t')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_00000000000000000000000000','cnt_00000000000000000000000000','note',1,'t','t')`,
		`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('d1',2,'t')`,
		`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES('d1','cnt_00000000000000000000000000','t')`,
		`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES('obj_00000000000000000000000000',1,'d1',2,1,1,'t')`,
		`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES('cfl_00000000000000000000000000','obj_00000000000000000000000000','cnt_00000000000000000000000000',0,1,'d1',2,1,1,'t')`,
		`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) VALUES('att_00000000000000000000000000','cnt_00000000000000000000000000','d1',2,X'',1,1,'t')`,
		`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at) VALUES('ups_00000000000000000000000000','usr_00000000000000000000000000','cnt_00000000000000000000000000',2,2,'t','t','t')`,
		`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('shl_00000000000000000000000000','h',X'00000000000000000000000000000000','2099-01-01T00:00:00Z','t','usr_00000000000000000000000000')`,
		`INSERT INTO audit_events(id,user_id,event,created_at,at,outcome) VALUES('aud_00000000000000000000000000','usr_00000000000000000000000000','prior','t','t','success')`,
	} {
		if _, err = s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestUpgradePutsEveryRowInTheDefaultOrg(t *testing.T) {
	SkipOnPostgres(t, "a SQLite install's upgrade")
	path := filepath.Join(t.TempDir(), "db.sqlite")
	legacyOrgDatabase(t, path)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for table := range orgOwned {
		if !s.pg && sqliteOmits[table] {
			continue
		}
		var total, inDefault int
		if err = s.db.QueryRow(`SELECT count(*),count(*) FILTER (WHERE org_id=?) FROM `+table, DefaultOrgID).Scan(&total, &inDefault); err != nil || total == 0 || total != inDefault {
			t.Errorf("%s: %d rows, %d in the default org: %v", table, total, inDefault, err)
		}
	}
	var mode, status, region string
	if err = s.db.QueryRow(`SELECT (SELECT value FROM server_settings WHERE key='tenancy_mode'),status,home_region FROM orgs`).Scan(&mode, &status, &region); err != nil || mode != "single" || status != "active" || region != "local" {
		t.Fatalf("mode=%q org=%q/%q: %v", mode, status, region, err)
	}
	// Cleanup sizes a row from SELECT *; the stored cell must hold exactly that, org_id included.
	for _, table := range []string{"containers", "sealed_share_links"} {
		rows, err := s.db.Query(`SELECT * FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		values, refs := make([]any, len(cols)), make([]any, len(cols))
		for i := range values {
			refs[i] = &values[i]
		}
		if !rows.Next() || rows.Scan(refs...) != nil {
			t.Fatalf("%s: no row", table)
		}
		rows.Close()
		var stored int
		if err = s.db.QueryRow(`SELECT max(mx_payload) FROM dbstat WHERE name=? AND pagetype='leaf'`, table).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if want := sqliteRecordBytes(values, 1); stored != want {
			t.Errorf("%s: stored record %d bytes, cleanup sizes it %d", table, stored, want)
		}
	}
}

func TestFreshDatabaseGetsTheDefaultOrg(t *testing.T) {
	s := openFresh(t)
	var mode string
	var orgs int
	if err := s.db.QueryRow(`SELECT (SELECT value FROM server_settings WHERE key='tenancy_mode'),(SELECT count(*) FROM orgs WHERE id=?)`, DefaultOrgID).Scan(&mode, &orgs); err != nil || mode != "single" || orgs != 1 {
		t.Fatalf("mode=%q orgs=%d: %v", mode, orgs, err)
	}
}

func snapshotRows(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var a, c, d any
		if err = rows.Scan(&a, &c, &d); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%v|%v|%v\n", a, c, d)
	}
	return b.String()
}

// A database recorded in another mode is refused, and the refused start writes nothing.
func TestOpenRefusesAnotherTenancyModeAndWritesNothing(t *testing.T) {
	for _, recorded := range []string{"multi", "other"} {
		t.Run(recorded, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db.sqlite")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(`UPDATE server_settings SET value=? WHERE key='tenancy_mode'`, recorded); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(`INSERT INTO orgs(id,status,home_region) VALUES('staff','active','eu')`); err != nil {
				t.Fatal(err)
			}
			const settings, orgs = `SELECT key,value,updated_at FROM server_settings ORDER BY key`, `SELECT id,status,home_region FROM orgs ORDER BY id`
			before := snapshotRows(t, s.db, settings) + snapshotRows(t, s.db, orgs)
			s.Close()
			if s, err = Open(path); !errors.Is(err, ErrTenancyMode) {
				if s != nil {
					s.Close()
				}
				t.Fatalf("open=%v, want ErrTenancyMode", err)
			}
			s, err = OpenUnmigrated(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if after := snapshotRows(t, s.db, settings) + snapshotRows(t, s.db, orgs); after != before {
				t.Fatalf("refused start wrote:\n%s\nwant\n%s", after, before)
			}
		})
	}
}

func TestOrgTriggersRefuseCrossOrgRows(t *testing.T) {
	s := openFresh(t)
	exec := func(q string, args ...any) error { _, err := s.db.Exec(q, args...); return err }
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region) VALUES('org_b','active','local')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','x','x',1,'t','t')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_b','b','x','x',1,'t','t','org_b')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_a','team','usr_a','t','t')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('cnt_b','team','usr_b','t','t','org_b')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_a','cnt_a','note',1,'t','t')`,
		`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('d1',2,'t')`,
	} {
		if err := exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for name, q := range map[string]string{
		"unknown org":                         `INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_x','x','x','x',1,'t','t','nowhere')`,
		"container in another org than owner": `INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('cnt_x','workbook','usr_a','t','t','org_b')`,
		"child in another org than its team":  `INSERT INTO containers(id,kind,owner_user_id,team_id,created_at,updated_at) VALUES('cnt_y','workbook','usr_a','cnt_b','t','t')`,
		"owner moved to another org":          `UPDATE containers SET owner_user_id='usr_b' WHERE id='cnt_a'`,
		"version in another org":              `INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('obj_a',1,'d1',2,1,1,'t','org_b')`,
		"blob link in another org":            `INSERT INTO blob_containers(digest,container_id,first_seen_at,org_id) VALUES('d1','cnt_a','t','org_b')`,
		"upload in another org":               `INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES('ups_x','usr_a','cnt_a',1,1,'t','t','t','org_b')`,
		"attachment in another org":           `INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at,org_id) VALUES('att_x','cnt_a','d1',1,X'',1,1,'t','org_b')`,
		"conflict in another org":             `INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('cfl_x','obj_a','cnt_a',0,1,'d1',1,1,1,'t','org_b')`,
		"sealed link in another org":          `INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id,org_id) VALUES('shl_x','h',X'00',  't','t','usr_a','org_b')`,
		"org_id moved":                        `UPDATE users SET org_id='org_b' WHERE id='usr_a'`,
		"blob org moved":                      `UPDATE blobs SET org_id='org_b' WHERE digest='d1'`,
		"customer audit row with no org":      `INSERT INTO audit_events(id,user_id,event,created_at,at,outcome,org_id) VALUES('aud_x','usr_a','e','t','t','success',NULL)`,
		"audit row in an unknown org":         `INSERT INTO audit_events(id,user_id,event,created_at,at,outcome,org_id) VALUES('aud_y','usr_a','e','t','t','success','nowhere')`,
	} {
		if err := exec(q); err == nil || !strings.Contains(err.Error(), "org") {
			t.Errorf("%s: %v, want an org trigger refusal", name, err)
		}
	}
	// N7: members, invitees and the devices behind envelopes are in the container's org.
	for _, q := range []string{
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_b','usr_b','k','f','h','identity','t')`,
		`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES('inv_x','cnt_a','usr_a','usr_b','th','viewer','t','t')`,
	} {
		if err := exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for name, q := range map[string]string{
		"member in another org":           `INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_x','cnt_a','usr_b','viewer','t')`,
		"invitation accepted across orgs": `UPDATE invitations SET status='accepted' WHERE id='inv_x'`,
		"key envelope for another org":    `INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('env_x','cnt_a','dev_b',1,'a',X'00','t')`,
		"device selection across orgs":    `INSERT INTO device_containers(device_id,container_id,selected_at) VALUES('dev_b','cnt_a','t')`,
		"invitation envelope across orgs": `INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES('inv_x','cnt_a','dev_b',1,'a',X'00')`,
	} {
		if err := exec(q); err == nil || !strings.Contains(err.Error(), "member in another org") {
			t.Errorf("%s: %v, want the N7 trigger", name, err)
		}
	}
	// The same rows inside one org pass.
	if err := exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_b','cnt_b','usr_b','viewer','t')`); err != nil {
		t.Fatalf("same-org member: %v", err)
	}
	// A blob claim names its key as PostgreSQL does: (org_id, digest).
	if err := exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('d1',2,'t') ON CONFLICT(org_id,digest) DO UPDATE SET unreferenced_since=''`); err != nil {
		t.Fatalf("claim by (org_id,digest): %v", err)
	}
	// Platform audit rows (no account, or an unknown actor such as "system") carry no org.
	if err := exec(`INSERT INTO audit_events(id,user_id,event,created_at,at,outcome,org_id) VALUES('aud_p','system','backup.run','t','t','success',NULL)`); err != nil {
		t.Fatalf("platform audit row: %v", err)
	}
	// Writers that name the org pass; so does a same-org re-point.
	if err := RecordAuditOutcome(s.db, "usr_a", "e", "", "", "success", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE containers SET team_id='' WHERE id='cnt_a'`); err != nil {
		t.Fatal(err)
	}
}

// Every audit writer names the org through AuditOrgSQL: the default org in single mode, the
// actor's org in multi mode, and NULL there for staff and for actors that are no account.
func TestAuditWritersNameTheOrg(t *testing.T) {
	s := openFresh(t)
	written := 0
	orgOf := func(actor string) string {
		t.Helper()
		// Each call's own event names the one row it wrote: audit times have one-second precision.
		written++
		event := fmt.Sprintf("test.event.%d", written)
		if err := RecordAuditOutcome(s.db, actor, event, "", "", "success", "", ""); err != nil {
			t.Fatal(err)
		}
		var org sql.NullString
		if err := s.db.QueryRow(`SELECT org_id FROM audit_events WHERE actor_user_id=? AND event=?`, actor, event).Scan(&org); err != nil {
			t.Fatal(err)
		}
		if !org.Valid {
			return "NULL"
		}
		return org.String
	}
	if got := orgOf("system"); got != DefaultOrgID {
		t.Fatalf("single mode, system: %s", got)
	}
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,home_region) VALUES('org_staff','active','eu'),('org_b','active','eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_cust','c','x','x',1,'t','t','org_b')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at,org_id) VALUES('usr_staff','s','x','x',1,'admin','admin','t','t','org_staff')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for actor, want := range map[string]string{"usr_cust": "org_b", "usr_staff": "NULL", "system": "NULL"} {
		if got := orgOf(actor); got != want {
			t.Errorf("multi mode, %s: org %s, want %s", actor, got, want)
		}
	}
}
