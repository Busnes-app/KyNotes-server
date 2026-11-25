package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/backup"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// A backup taken before an org purge and a member's erasure is restored: no customer org
// serves until both suite feeds were replayed from zero, the erased member is fenced before
// their org serves again, and the deleted org is purged again.
func TestRestoreAfterPurgeReplaysBeforeServing(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("PostgreSQL backup and restore")
	}
	ctx := t.Context()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since := r.URL.Query().Get("since")
		switch r.URL.Path {
		case "/api/suite/orgs":
			orgs := []map[string]any{}
			if since == "0" {
				orgs = append(orgs,
					map[string]any{"id": storage.DefaultOrgID, "status": "active", "revision": 15, "home_region": "local", "enabled": true, "quotas": map[string]any{}},
					map[string]any{"id": "org_gone", "status": "deleted", "revision": 16, "home_region": "local", "enabled": true, "quotas": map[string]any{}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"orgs": orgs, "next": ""})
		case "/api/suite/erased":
			if since == "0" {
				feedNotice(w, "erased-person", storage.DefaultOrgID, 14)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"subjects": []suitedir.ErasedSubject{}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	dir := suitedir.Client{Issuer: srv.URL, ClientID: "notes", ClientSecret: "test-client-secret", HTTP: srv.Client()}

	p := newPairClient(t, strings.Repeat("p", 32))
	seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	bindErasedSubject(t, p.db, dir.Issuer)
	toMultiMode(t, p.db, "org_staff")
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region,revision) VALUES('org_gone','active','local',3)`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_gone','gone','x','x',1,'t','t','org_gone')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('ctr_gone','workbook','usr_gone','t','t','org_gone')`,
	} {
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	key := bytes.Repeat([]byte{5}, backup.BackupKeyBytes)
	var archive bytes.Buffer
	if _, err := backup.BackupPostgres(ctx, p.db, key, &archive); err != nil {
		t.Fatal(err)
	}
	noObjects := func(context.Context, string) error { return nil }
	if _, err := p.db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_gone'`); err != nil {
		t.Fatal(err)
	}
	if err := storage.PurgeDeletedOrgs(ctx, p.db, noObjects); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, p.db, `SELECT count(*) FROM users WHERE org_id='org_gone'`) != 0 {
		t.Fatal("the source purge left the org's account")
	}

	target, err := storage.Open(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	db := target.DB()
	if _, err := backup.RestorePostgres(ctx, db, key, &archive); err != nil {
		t.Fatal(err)
	}
	served := func() bool {
		return erasedCount(t, db, `SELECT count(*) FROM orgs o WHERE o.id=? AND `+storage.OrgServes("o.id"), storage.DefaultOrgID) == 1
	}
	gated := func() bool {
		return erasedCount(t, db, `SELECT count(*) FROM server_settings WHERE key=?`, storage.RestoreReplayKey) == 1
	}
	if served() || !gated() || erasedCount(t, db, `SELECT count(*) FROM users WHERE org_id='org_gone'`) != 1 {
		t.Fatal("the restored target is not stale, gated and holding the purged org")
	}
	if err := FinishRestoreReplay(ctx, db, dir); err != nil || !gated() {
		t.Fatalf("gate lifted before any poll: %v", err)
	}
	if err := orgsync.New(db, dir.Orgs).Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if served() {
		t.Fatal("the org serves before its erasures were replayed")
	}
	if err := FinishRestoreReplay(ctx, db, dir); err != nil || !gated() {
		t.Fatalf("gate lifted with erasures pending: %v", err)
	}
	if err := PollErased(ctx, db, dir); err != nil {
		t.Fatal(err)
	}
	if err := FinishRestoreReplay(ctx, db, dir); err != nil || gated() {
		t.Fatalf("gate kept after both feeds were replayed: %v", err)
	}
	if !served() || erasedCount(t, db, `SELECT count(*) FROM users WHERE id=? AND status='erased'`, pairUser) != 1 {
		t.Fatal("after the replay the org must serve and the member stay erased")
	}
	if erasedCount(t, db, `SELECT count(*) FROM audit_events WHERE event='platform.restore_replayed' AND org_id IS NULL`) != 1 {
		t.Fatal("replay not audited")
	}
	if err := storage.PurgeDeletedOrgs(ctx, db, noObjects); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, db, `SELECT count(*) FROM users WHERE org_id='org_gone'`)+erasedCount(t, db, `SELECT count(*) FROM containers WHERE org_id='org_gone'`) != 0 {
		t.Fatal("the restored deleted org was not purged again")
	}
	// The org feed alone still listing changes keeps the gate as well.
	if _, err := db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES(?,'pending','t')`, storage.RestoreReplayKey); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM server_settings WHERE key='org_poll_revision'`); err != nil {
		t.Fatal(err)
	}
	if err := FinishRestoreReplay(ctx, db, dir); err != nil || !gated() {
		t.Fatalf("gate lifted with org changes pending: %v", err)
	}
}
