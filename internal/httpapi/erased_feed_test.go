package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func erasedDirectory(t *testing.T, reply http.HandlerFunc) suitedir.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "notes" || secret != "test-client-secret" || r.URL.Path != "/api/suite/erased" {
			t.Errorf("unexpected suite request %s", r.URL.Path)
			w.WriteHeader(401)
			return
		}
		reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return suitedir.Client{Issuer: srv.URL, ClientID: "notes", ClientSecret: "test-client-secret", HTTP: srv.Client()}
}
func feedNotice(w http.ResponseWriter, subject, org string, revision int64) {
	_ = json.NewEncoder(w).Encode(map[string]any{"subjects": []suitedir.ErasedSubject{{Sub: subject, OrgID: org, Revision: revision}}})
}
func bindErasedSubject(t *testing.T, db *sql.DB, issuer string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE users SET sso_issuer=?,sso_subject='erased-person' WHERE id=?`, issuer, pairUser); err != nil {
		t.Fatal(err)
	}
}
func erasedCount(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestErasedFeedTransfersSharedContentAndIsReplaySafe(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	page, code := tm.owner.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	sole := seedContainer(t, tm.owner, "workbook", "", map[string]string{pairUser: "owner"})
	var calls atomic.Int32
	dir := erasedDirectory(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("since") == "0" {
			feedNotice(w, "erased-person", storage.DefaultOrgID, 11)
		} else {
			if r.URL.Query().Get("since") != "11" {
				t.Errorf("cursor=%s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"subjects":[]}`))
		}
	})
	bindErasedSubject(t, tm.owner.db, dir.Issuer)
	toMultiMode(t, tm.owner.db, "org_staff")
	if err := PollErased(t.Context(), tm.owner.db, dir); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, tm.owner.db, `SELECT count(*) FROM users WHERE id=? AND status='erased'`, pairUser) != 1 {
		t.Fatal("account retained access")
	}
	if erasedCount(t, tm.owner.db, `SELECT count(*) FROM sessions WHERE user_id=? AND revoked_at=''`, pairUser) != 0 {
		t.Fatal("session survived")
	}
	var owner string
	if err := tm.owner.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, tm.id).Scan(&owner); err != nil || owner != tm.admin.id {
		t.Fatalf("successor %q %v", owner, err)
	}
	if code, body := status(t, tm.admin.do(t, http.MethodGet, "/api/v1/objects/"+page, nil, false, false)); code != 200 {
		t.Fatalf("shared page lost: %d %s", code, body)
	}
	if err := storage.EraseMembers(t.Context(), tm.owner.db); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, tm.owner.db, `SELECT count(*) FROM containers WHERE id=?`, sole) != 0 {
		t.Fatal("sole notebook survived")
	}
	if err := PollErased(t.Context(), tm.owner.db, dir); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || erasedCount(t, tm.owner.db, `SELECT count(*) FROM erased_subjects WHERE subject='erased-person'`) != 1 || erasedCount(t, tm.owner.db, `SELECT count(*) FROM audit_events WHERE action='directory.erase_reconcile'`) != 1 {
		t.Fatal("replay changed erasure state")
	}
}

func TestErasedFeedAtomicFailureWrongOrgAndUnknownSubject(t *testing.T) {
	for _, kind := range []string{"audit", "wrong-org", "unknown", "malformed", "unauthorized"} {
		t.Run(kind, func(t *testing.T) {
			p := newPairClient(t, strings.Repeat("p", 32))
			dir := erasedDirectory(t, func(w http.ResponseWriter, r *http.Request) {
				if kind == "unauthorized" {
					w.WriteHeader(401)
					return
				}
				if kind == "malformed" {
					_, _ = w.Write([]byte(`{"subjects":[{"sub":"erased-person","org_id":"../wrong","revision":12}]}`))
					return
				}
				subject, org := "erased-person", storage.DefaultOrgID
				if kind == "wrong-org" {
					org = "00000000-0000-0000-0000-000000000002"
				}
				if kind == "unknown" {
					subject = "not-yet-provisioned"
				}
				feedNotice(w, subject, org, 12)
			})
			bindErasedSubject(t, p.db, dir.Issuer)
			toMultiMode(t, p.db, "org_staff")
			if kind == "audit" {
				refuseTrigger(t, p.db, "deny_erased_audit", "BEFORE INSERT", "audit_events", "NEW.action='directory.erase_reconcile'", "test audit unavailable")
			}
			err := PollErased(t.Context(), p.db, dir)
			if kind == "unknown" {
				if err != nil || erasedCount(t, p.db, `SELECT count(*) FROM erased_subjects WHERE subject='not-yet-provisioned'`) != 1 {
					t.Fatalf("missing unknown-subject fence: %v", err)
				}
				if erasedCount(t, p.db, `SELECT count(*) FROM users WHERE sso_subject='not-yet-provisioned'`) != 0 {
					t.Fatal("feed provisioned an account")
				}
			} else {
				if err == nil {
					t.Fatal("bad erasure accepted")
				}
				if erasedCount(t, p.db, `SELECT count(*) FROM erased_subjects`) != 0 || erasedCount(t, p.db, `SELECT count(*) FROM server_settings WHERE key=?`, erasedCursor) != 0 {
					t.Fatal("failed batch advanced fence or cursor")
				}
			}
			if erasedCount(t, p.db, `SELECT count(*) FROM users WHERE id=? AND status='active'`, pairUser) != 1 {
				t.Fatal("failed/unknown notice changed account")
			}
		})
	}
}

func TestErasedFeedConcurrentPoolsCommitOnce(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs independent PostgreSQL pools")
	}
	p := newPairClient(t, strings.Repeat("p", 32))
	other := replicaDB(t, p.db)
	var fetched atomic.Int32
	both := make(chan struct{})
	dir := erasedDirectory(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("since") != "0" {
			t.Errorf("unexpected cursor %s", r.URL.RawQuery)
		}
		if fetched.Add(1) == 2 {
			close(both)
		}
		select {
		case <-both:
			feedNotice(w, "erased-person", storage.DefaultOrgID, 13)
		case <-r.Context().Done():
		}
	})
	bindErasedSubject(t, p.db, dir.Issuer)
	toMultiMode(t, p.db, "org_staff")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, db := range []*sql.DB{p.db, other} {
		wg.Add(1)
		go func(db *sql.DB) {
			defer wg.Done()
			if err := PollErased(ctx, db, dir); err != nil {
				t.Error(err)
			}
		}(db)
	}
	wg.Wait()
	if fetched.Load() != 2 || erasedCount(t, p.db, `SELECT count(*) FROM audit_events WHERE action='directory.erase_reconcile'`) != 1 {
		t.Fatal("stale worker applied erasure twice")
	}
}

func TestErasedFeedAfterRestoreReplaysFromZero(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("PostgreSQL restore boundary")
	}
	p := newPairClient(t, strings.Repeat("p", 32))
	dir := erasedDirectory(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("since") != "0" {
			t.Errorf("restore retained cursor: %s", r.URL.RawQuery)
		}
		feedNotice(w, "erased-person", storage.DefaultOrgID, 14)
	})
	bindErasedSubject(t, p.db, dir.Issuer)
	toMultiMode(t, p.db, "org_staff")
	for _, q := range []string{`UPDATE orgs SET revision=90`, `INSERT INTO orgs(id,status,home_region,revision) VALUES('org_missing','active','local',91)`, `INSERT INTO server_settings(key,value,updated_at) VALUES('erased_poll_revision','999','t'),('org_poll_revision','999','t')`} {
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := p.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.ResetTenancyAfterRestore(t.Context(), tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	poll := orgsync.New(p.db, func(_ context.Context, since int64) ([]suitedir.Org, int64, error) {
		if since != 0 {
			t.Errorf("org cursor=%d", since)
		}
		return []suitedir.Org{{ID: storage.DefaultOrgID, Status: "active", Enabled: true, HomeRegion: "local", Revision: 15}}, 15, nil
	})
	if err := poll.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := PollErased(t.Context(), p.db, dir); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, p.db, `SELECT count(*) FROM orgs missing WHERE missing.id='org_missing' AND missing.status='stale' AND NOT `+storage.OrgServes("missing.id")) != 1 {
		t.Fatal("unlisted restored org served")
	}
	if erasedCount(t, p.db, `SELECT count(*) FROM users WHERE id=? AND status='erased'`, pairUser) != 1 {
		t.Fatal("restored subject was not erased")
	}
	if erasedCount(t, p.db, `SELECT count(*) FROM erased_subjects WHERE subject='erased-person'`) != 1 {
		t.Fatal("restore replay lost fence")
	}
}

func TestErasedFeedSingleModeDoesNothing(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	dir := erasedDirectory(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("single mode fetched erasures")
		w.WriteHeader(500)
	})
	before := erasedCount(t, p.db, `SELECT count(*) FROM audit_events`)
	if err := PollErased(t.Context(), p.db, dir); err != nil {
		t.Fatal(err)
	}
	if erasedCount(t, p.db, `SELECT count(*) FROM server_settings WHERE key=?`, erasedCursor) != 0 || erasedCount(t, p.db, `SELECT count(*) FROM audit_events`) != before {
		t.Fatal("single mode changed durable state")
	}
}
