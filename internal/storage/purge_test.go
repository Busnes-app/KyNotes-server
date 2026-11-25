package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// seedPurgeOrg puts one row of everything a purge must reach into org, IDs prefixed by tag.
func seedPurgeOrg(t *testing.T, s *Store, org, tag string) []string {
	t.Helper()
	id := func(kind string) string { return kind + "_" + tag }
	u, u2, c, o, cm, a, d, ses, inv := id("usr"), id("usr2"), id("cnt"), id("obj"), id("cmt"), id("att"), id("dev"), id("ses"), id("inv")
	digest := strings.Repeat(tag[:1], 64)
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region) VALUES('` + org + `','active','eu') ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id,sso_issuer,sso_subject) VALUES('` + u + `','name-` + u + `','x','x',1,'t','t','` + org + `','iss','sub-` + tag + `'),('` + u2 + `','name-` + u2 + `','x','x',1,'t','t','` + org + `','','')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('` + c + `','team','` + u + `','t','t','` + org + `')`,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('` + id("mem") + `','` + c + `','` + u + `','owner','t'),('` + id("mem2") + `','` + c + `','` + u2 + `','editor','t')`,
		`INSERT INTO objects(id,container_id,kind,current_version,change_seq,created_at,updated_at) VALUES('` + o + `','` + c + `','note',1,1,'t','t')`,
		`INSERT INTO blobs(digest,size_bytes,created_at,org_id) VALUES('` + digest + `',2,'t','` + org + `')`,
		`INSERT INTO blob_containers(digest,container_id,first_seen_at,org_id) VALUES('` + digest + `','` + c + `','t','` + org + `')`,
		`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('` + o + `',1,'` + digest + `',2,1,1,'t','` + org + `')`,
		`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('` + id("cfl") + `','` + o + `','` + c + `',0,1,'` + digest + `',2,1,1,'t','` + org + `')`,
		`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES('` + cm + `','` + c + `','` + o + `','` + u + `',X'6374',1,1,'t')`,
		`INSERT INTO mentions(comment_id,mentioned_user_id) VALUES('` + cm + `','` + u2 + `')`,
		`INSERT INTO activity(id,container_id,actor_user_id,event,change_seq,created_at) VALUES('` + id("act") + `','` + c + `','` + u + `','e',1,'t')`,
		`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at,org_id) VALUES('` + a + `','` + c + `','` + digest + `',2,X'',1,1,'t','` + org + `')`,
		`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) VALUES('` + a + `','` + o + `',1,'t')`,
		`INSERT INTO share_links(id,token_hash,object_id,object_version,expires_at,created_at) VALUES('` + id("lnk") + `','th-` + tag + `','` + o + `',1,'2099','t')`,
		`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES('` + id("ups") + `','` + u + `','` + c + `',2,2,'t','t','t','` + org + `')`,
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('` + d + `','` + u + `','k','f-` + tag + `','h','unknown','t'),('` + id("idk") + `','` + u + `','k','g-` + tag + `','h','identity','t')`,
		`INSERT INTO user_identities(user_id,device_id,wrapped_private_key,wrap_alg,created_at,updated_at) VALUES('` + u + `','` + id("idk") + `',X'00','none','t','t')`,
		`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('` + id("env") + `','` + c + `','` + d + `',1,'a',X'00','t')`,
		`INSERT INTO device_containers(device_id,container_id,selected_at) VALUES('` + d + `','` + c + `','t')`,
		`INSERT INTO push_registrations(device_id,transport,token,updated_at) VALUES('` + d + `','apns','tok','t')`,
		`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES('` + inv + `','` + c + `','` + u + `','` + u2 + `','it-` + tag + `','viewer','t','2099')`,
		`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES('` + inv + `','` + c + `','` + d + `',1,'a',X'00')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('` + ses + `','` + u + `','sh-` + tag + `','c','t','2099','2099')`,
		`INSERT INTO sso_stepup(id,session_id,action,created_at,expires_at) VALUES('` + id("rea") + `','` + ses + `','user',1,2)`,
		`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES('` + id("lrq") + `','` + u + `','` + ses + `',X'00','t','2099')`,
		`INSERT INTO reminders(id,user_id,at,created_at) VALUES('` + id("rmd") + `','` + u + `','2099','t')`,
		`INSERT INTO web_push_subscriptions(id,user_id,endpoint,created_at) VALUES('` + id("wps") + `','` + u + `','https://push.example/` + tag + `','t')`,
		`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id,org_id) VALUES('` + id("shl") + `','st-` + tag + `',X'00','2099','t','` + u + `','` + org + `')`,
		`INSERT INTO pairing_nonces(nonce,purpose,user_id,used_at,expires_at) VALUES('n-` + tag + `','p','` + u + `','t','2099')`,
		`INSERT INTO sso_directory_state(issuer,subject,revision,digest,active,event_id) VALUES('iss','sub-` + tag + `',1,'d',1,'e')`,
		`INSERT INTO sso_login_cutoffs(issuer,subject,revoked_before) VALUES('iss','sub-` + tag + `',1)`,
		`INSERT INTO audit_events(id,user_id,event,created_at,at,outcome,org_id) VALUES('` + id("aud") + `','` + u + `','e','t','t','success','` + org + `')`,
		`INSERT INTO org_pool(org_id,seq,expires_at) VALUES('` + org + `',1,'pool-` + tag + `')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%.90s: %v", q, err)
		}
	}
	if s.pg {
		if _, err := s.db.Exec(`INSERT INTO replica_presence(user_id,container_id,state,expires_at) VALUES(?,?,?,9999999999)`, u, c, "editing"); err != nil {
			t.Fatal(err)
		}
	}
	return []string{u, u2, c, o, cm, a, d, ses, inv, digest, "sub-" + tag, "pool-" + tag}
}

// everyValue is every table's values, bar the rows a purge keeps on purpose (the tombstone, the
// erased subjects, platform audit rows and the install's own settings).
func everyValue(t *testing.T, s *Store, skip ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range catalogTables(t, s) {
		switch table {
		case "orgs", "erased_subjects", "schema_migrations", "server_settings":
			continue
		}
		if slices.Contains(skip, table) {
			continue
		}
		q := `SELECT * FROM ` + table
		if table == "audit_events" {
			q += ` WHERE org_id IS NOT NULL`
		}
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals, refs := make([]any, len(cols)), make([]any, len(cols))
			for i := range vals {
				refs[i] = &vals[i]
			}
			if err := rows.Scan(refs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				if b, ok := v.([]byte); ok {
					v = string(b)
				}
				out[fmt.Sprint(v)] = table
			}
		}
		rows.Close()
	}
	return out
}

func purgeFixture(t *testing.T) (*Store, []string, map[string]string) {
	t.Helper()
	s := openFresh(t)
	for _, q := range []string{`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('staff_org_id','org_staff','t')`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	seedPurgeOrg(t, s, "org_a", "aaa")
	bIDs := seedPurgeOrg(t, s, "org_b", "bbb")
	before := everyValue(t, s)
	if _, err := s.db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	return s, bIDs, before
}

func assertPurged(t *testing.T, s *Store, bIDs []string, before map[string]string) {
	t.Helper()
	after := everyValue(t, s)
	for _, id := range bIDs {
		if table, ok := after[id]; ok {
			t.Errorf("%s survived the purge in %s", id, table)
		}
	}
	for v, table := range before {
		if strings.Contains(v, "aaa") || strings.Contains(v, "org_a") {
			if _, ok := after[v]; !ok {
				t.Errorf("the purge of org_b removed org_a's %q from %s", v, table)
			}
		}
	}
	var purgedAt string
	var deletedAudit int
	if err := s.db.QueryRow(`SELECT purged_at,(SELECT count(*) FROM audit_events WHERE event='platform.org_deleted' AND object_id='org_b' AND org_id IS NULL) FROM orgs WHERE id='org_b'`).Scan(&purgedAt, &deletedAudit); err != nil || purgedAt == "" || deletedAudit != 1 {
		t.Fatalf("tombstone purged_at=%q, org_deleted audits=%d, %v", purgedAt, deletedAudit, err)
	}
}

// A purge leaves no row of the deleted org, keeps its tombstone, and touches no other org.
func TestPurgeLeavesNoRowOfTheOrg(t *testing.T) {
	s, bIDs, before := purgeFixture(t)
	if err := PurgeDeletedOrgs(context.Background(), s.db, noObjects); err != nil {
		t.Fatal(err)
	}
	var purgedAt string
	var users, started int
	if err := s.db.QueryRow(`SELECT purged_at,(SELECT count(*) FROM users WHERE org_id='org_b'),(SELECT count(*) FROM audit_events WHERE event='platform.org_purge_started' AND object_id='org_b') FROM orgs WHERE id='org_b'`).Scan(&purgedAt, &users, &started); err != nil || purgedAt != "" || users != 0 || started != 1 {
		t.Fatalf("inside the late-PUT window: purged_at=%q users=%d started=%d %v", purgedAt, users, started, err)
	}
	if err := PurgeDeletedOrgs(context.Background(), s.db, noObjects); err != nil {
		t.Fatal(err)
	}
	endPurgeWindow(t, s)
	if err := PurgeDeletedOrgs(context.Background(), s.db, noObjects); err != nil {
		t.Fatal(err)
	}
	assertPurged(t, s, bIDs, before)
	var fences int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM server_settings WHERE key LIKE 'purge_fence:%'),(SELECT count(*) FROM audit_events WHERE event='platform.org_purge_started' AND object_id='org_b')`).Scan(&fences, &started); err != nil || fences != 0 || started != 1 {
		t.Fatalf("fence rows=%d started audits=%d %v", fences, started, err)
	}
}

// endPurgeWindow moves every purge fence back past the late-PUT window.
func endPurgeWindow(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE server_settings SET value='0' WHERE key LIKE 'purge_fence:%'`); err != nil {
		t.Fatal(err)
	}
}

// A purge killed between batches finishes on its next run.
func TestPurgeKilledBetweenBatchesFinishesNextRun(t *testing.T) {
	s, bIDs, before := purgeFixture(t)
	purgeBatch = 1
	calls := 0
	purgeBatchHook = func(table string) error {
		calls++
		if calls == 12 {
			return errors.New("killed")
		}
		return nil
	}
	t.Cleanup(func() { purgeBatch, purgeBatchHook = 500, func(string) error { return nil } })
	if err := PurgeDeletedOrgs(context.Background(), s.db, noObjects); err == nil {
		t.Fatal("the killed purge reported success")
	}
	var purgedAt string
	if err := s.db.QueryRow(`SELECT purged_at FROM orgs WHERE id='org_b'`).Scan(&purgedAt); err != nil || purgedAt != "" {
		t.Fatalf("a killed purge marked the org purged: %q %v", purgedAt, err)
	}
	purgeBatchHook = func(string) error { return nil }
	endPurgeWindow(t, s)
	if err := PurgeDeletedOrgs(context.Background(), s.db, noObjects); err != nil {
		t.Fatal(err)
	}
	assertPurged(t, s, bIDs, before)
	// The completion audit counts the rows of both runs, and no progress row is left.
	var counts string
	var left int
	if err := s.db.QueryRow(`SELECT reason_code,(SELECT count(*) FROM server_settings WHERE key LIKE 'purge_rows:%') FROM audit_events WHERE event='platform.org_deleted' AND object_id='org_b'`).Scan(&counts, &left); err != nil || left != 0 {
		t.Fatalf("counts %q, %d progress rows left (%v)", counts, left, err)
	}
	for _, want := range []string{"activity=1", "comments=1", "containers=1", "users=2", "audit_events=1"} {
		if !strings.Contains(","+counts+",", ","+want+",") {
			t.Errorf("the completion audit %q lacks %s", counts, want)
		}
	}
}

// Every table with a foreign key to a purged table is in the purge order, so a new child table
// cannot be left behind (or block a parent's delete).
func TestPurgeOrderCoversEveryCascade(t *testing.T) {
	s := openFresh(t)
	purged := map[string]bool{}
	for _, step := range purgeStepsFor(s.db) {
		purged[step.table] = true
	}
	q := `SELECT m.name,f."table" FROM sqlite_schema m, pragma_foreign_key_list(m.name) f WHERE m.type='table'`
	if s.pg {
		q = `SELECT tc.table_name,ccu.table_name FROM information_schema.table_constraints tc JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name=tc.constraint_name AND ccu.table_schema=tc.table_schema WHERE tc.constraint_type='FOREIGN KEY' AND tc.table_schema=current_schema()`
	}
	rows, err := s.db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			t.Fatal(err)
		}
		checked++
		if purged[parent] && !purged[child] && !offInMulti[child] {
			t.Errorf("%s references %s but is not in the purge order", child, parent)
		}
	}
	if checked < 20 {
		t.Fatalf("read only %d foreign keys", checked)
	}
}

// Each purge step deletes by a key that names one row (the table's primary key or a unique
// index), so a batch of purgeBatch keys deletes at most purgeBatch rows.
func TestPurgeStepKeysAreUnique(t *testing.T) {
	s := openFresh(t)
	unique := func(table, key string) bool {
		want := strings.ReplaceAll(key, ",", " ")
		q := `SELECT group_concat(name,' ') FROM (SELECT name FROM pragma_table_info(?) WHERE pk>0 ORDER BY pk)
UNION ALL SELECT (SELECT group_concat(name,' ') FROM (SELECT name FROM pragma_index_info(il.name) ORDER BY seqno)) FROM pragma_index_list(?) il WHERE il."unique"=1`
		if s.pg {
			q = `SELECT string_agg(a.attname,' ' ORDER BY k.ord) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum,ord) JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum WHERE c.relname=? AND c.relnamespace=current_schema()::regnamespace AND i.indisunique AND i.indexprs IS NULL AND i.indpred IS NULL AND ?<>'' GROUP BY i.indexrelid`
		}
		rows, err := s.db.Query(q, table, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var cols sql.NullString
			if err := rows.Scan(&cols); err != nil {
				t.Fatal(err)
			}
			if cols.String == want {
				return true
			}
		}
		return false
	}
	for _, step := range append(append([]purgeStep{}, purgeStepsFor(s.db)...), eraseStepsFor(s.db)...) {
		if !unique(step.table, step.key) {
			t.Errorf("purge step %s: key (%s) is not a unique key", step.table, step.key)
		}
	}
}

// A member's erasure killed between batches finishes on its next run, and leaves no row of its
// account; another org is untouched.
func TestEraseMembersKilledBetweenBatchesFinishesNextRun(t *testing.T) {
	s, _, _ := purgeFixture(t)
	before := everyValue(t, s, "audit_events")
	if _, err := s.db.Exec(`UPDATE orgs SET status='active' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET status='erased' WHERE id='usr_bbb'`); err != nil {
		t.Fatal(err)
	}
	purgeBatch = 1
	calls := 0
	purgeBatchHook = func(string) error {
		if calls++; calls == 6 {
			return errors.New("killed")
		}
		return nil
	}
	t.Cleanup(func() { purgeBatch, purgeBatchHook = 500, func(string) error { return nil } })
	if err := EraseMembers(context.Background(), s.db); err == nil {
		t.Fatal("the killed erasure reported success")
	}
	purgeBatchHook = func(string) error { return nil }
	if err := EraseMembers(context.Background(), s.db); err != nil {
		t.Fatal(err)
	}
	// Audit rows keep the random ID, which names nobody once the account is deleted (as
	// object_versions.author_user_id does; spec, A member erases).
	after := everyValue(t, s, "audit_events")
	for _, gone := range []string{"cnt_bbb", "obj_bbb", "cmt_bbb", "sub-bbb", "dev_bbb", "ses_bbb"} {
		if table, ok := after[gone]; ok {
			t.Errorf("%s survived the erasure in %s", gone, table)
		}
	}
	// The account row stays, scrubbed to its random ID (owner decision 12).
	var username, subject string
	if err := s.db.QueryRow(`SELECT username,sso_subject FROM users WHERE id='usr_bbb'`).Scan(&username, &subject); err != nil || username != "usr_bbb" || subject != "" {
		t.Fatalf("the erased account: %q %q (%v)", username, subject, err)
	}
	for v := range before {
		if strings.Contains(v, "aaa") {
			if _, ok := after[v]; !ok {
				t.Errorf("erasing org_b's member removed org_a's %q", v)
			}
		}
	}
}

// noObjects is a purge's object step for row-only tests; internal/blobstore tests the real one.
func noObjects(context.Context, string) error { return nil }

func TestPurgeRefusesWithoutObjectsAndKeepsTheOrgUnpurged(t *testing.T) {
	s, _, _ := purgeFixture(t)
	if err := PurgeDeletedOrgs(context.Background(), s.db, nil); err == nil {
		t.Fatal("a purge without an object store succeeded")
	}
	var users int
	if err := s.db.QueryRow(`SELECT count(*) FROM users WHERE org_id='org_b'`).Scan(&users); err != nil || users != 2 {
		t.Fatalf("a purge without an object store deleted rows: users=%d %v", users, err)
	}
	failing := func(context.Context, string) error { return errors.New("bucket down") }
	if err := PurgeDeletedOrgs(context.Background(), s.db, failing); err == nil {
		t.Fatal("a failed prefix delete reported success")
	}
	var purgedAt string
	if err := s.db.QueryRow(`SELECT purged_at FROM orgs WHERE id='org_b'`).Scan(&purgedAt); err != nil || purgedAt != "" {
		t.Fatalf("org marked purged with its objects left: %q %v", purgedAt, err)
	}
}

// An org no longer deleted when the batches end keeps its objects, and one that changes during
// the prefix delete is not marked purged: both decisions re-read the status.
func TestPurgeRereadsTheStatusBeforeThePrefixAndTheMark(t *testing.T) {
	s, _, _ := purgeFixture(t)
	endPurgeWindow(t, s)
	restore := func() {
		if _, err := s.db.Exec(`UPDATE orgs SET status='active' WHERE id='org_b'`); err != nil {
			t.Error(err)
		}
	}
	purgeBatchHook = func(table string) error {
		if table == "users" {
			restore()
		}
		return nil
	}
	t.Cleanup(func() { purgeBatchHook = func(string) error { return nil } })
	called := false
	objects := func(context.Context, string) error { called = true; return nil }
	if err := PurgeOrg(context.Background(), s.db, objects, "org_b"); err == nil || called {
		t.Fatalf("prefix deleted for an org no longer deleted: err=%v called=%v", err, called)
	}
	purgeBatchHook = func(string) error { return nil }
	if _, err := s.db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	endPurgeWindow(t, s)
	flip := func(context.Context, string) error { restore(); return nil }
	if err := PurgeOrg(context.Background(), s.db, flip, "org_b"); err == nil {
		t.Fatal("an org restored during the prefix delete was marked purged")
	}
	var purgedAt string
	if err := s.db.QueryRow(`SELECT purged_at FROM orgs WHERE id='org_b'`).Scan(&purgedAt); err != nil || purgedAt != "" {
		t.Fatalf("purged_at=%q %v", purgedAt, err)
	}
}
