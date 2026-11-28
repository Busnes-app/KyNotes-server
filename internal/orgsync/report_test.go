package orgsync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// fakePool is KyIdentity's POST /api/suite/storage: it records each request and answers with
// answer(report), the report it was sent.
type fakePool struct {
	mu       sync.Mutex
	requests [][]map[string]any
	answer   func(r map[string]any) map[string]any
}

func (f *fakePool) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "kynotes" || pass != "suite-secret" || r.URL.Path != "/api/suite/storage" || r.Method != http.MethodPost {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var in struct {
			Reports []map[string]any `json:"reports"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.requests = append(f.requests, in.Reports)
		f.mu.Unlock()
		var out []map[string]any
		for _, rep := range in.Reports {
			out = append(out, f.answer(rep))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func okAnswer(rep map[string]any) map[string]any {
	return map[string]any{"org_id": rep["org_id"], "result": "ok", "seq": rep["seq"], "ceiling_bytes": 5000, "ttl_seconds": 900, "pool_bytes": 20 << 30, "org_used_bytes": 0, "over_since": nil}
}

func poolStore(t *testing.T) *Reporter {
	t.Helper()
	s := open(t)
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,home_region) VALUES('org_staff','active','eu'),('org_a','active','eu'),('org_off','suspended','eu')`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return &Reporter{DB: s.DB()}
}

func storedGrant(t *testing.T, r *Reporter, org string) (seq, ceiling int64, expires string) {
	t.Helper()
	if err := r.DB.QueryRow(`SELECT seq,ceiling_bytes,expires_at FROM org_pool WHERE org_id=?`, org).Scan(&seq, &ceiling, &expires); err != nil {
		t.Fatal(err)
	}
	return
}

// A serving customer org is reported with the contract's four fields and a rising seq; its grant
// is stored with an expiry counted from the send; an unchanged org is not reported again; the
// staff org and a stopped org are never reported.
func TestReportStoresTheGrant(t *testing.T) {
	r := poolStore(t)
	pool := &fakePool{answer: okAnswer}
	r.Dir = suitedir.Client{Issuer: pool.serve(t).URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
	sent := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return sent }
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pool.requests) != 1 || len(pool.requests[0]) != 1 {
		t.Fatalf("requests %v, want one report for org_a only", pool.requests)
	}
	rep := pool.requests[0][0]
	if len(rep) != 4 || rep["org_id"] != "org_a" || rep["used_bytes"] != float64(0) || rep["seq"] != float64(1) || rep["want_bytes"] != float64(minWant) {
		t.Fatalf("report %v", rep)
	}
	seq, ceiling, expires := storedGrant(t, r, "org_a")
	if seq != 1 || ceiling != 5000 || expires != sent.Add(900*time.Second).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("stored seq=%d ceiling=%d expires=%q", seq, ceiling, expires)
	}
	if err := r.Report(context.Background()); err != nil || len(pool.requests) != 1 {
		t.Fatalf("an unchanged org was reported again: %d requests %v", len(pool.requests), err)
	}
	// Half way to expiry it is reported again, with the next seq.
	r.now = func() time.Time { return sent.Add(451 * time.Second) }
	if err := r.Report(context.Background()); err != nil || len(pool.requests) != 2 || pool.requests[1][0]["seq"] != float64(2) {
		t.Fatalf("the half-expired grant: %d requests %v", len(pool.requests), err)
	}
}

// An answer that does not match the reports (here, a seq not echoed) is applied not at all; an
// unknown_org answer stores no headroom; single mode reports nothing.
func TestReportRefusesAMismatchedAnswer(t *testing.T) {
	r := poolStore(t)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	pool := &fakePool{answer: func(rep map[string]any) map[string]any {
		a := okAnswer(rep)
		a["seq"] = 99
		return a
	}}
	r.Dir = suitedir.Client{Issuer: pool.serve(t).URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
	if err := r.Report(context.Background()); err == nil {
		t.Fatal("a mismatched answer was accepted")
	}
	if _, ceiling, expires := storedGrant(t, r, "org_a"); ceiling != 0 || expires != "" {
		t.Fatalf("a refused answer stored a grant: %d %q", ceiling, expires)
	}
	pool.answer = func(rep map[string]any) map[string]any {
		return map[string]any{"org_id": rep["org_id"], "result": "unknown_org"}
	}
	now = now.Add(time.Minute)
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ceiling, _ := storedGrant(t, r, "org_a"); ceiling != 0 {
		t.Fatalf("unknown_org left headroom %d", ceiling)
	}
	if _, err := r.DB.Exec(`UPDATE server_settings SET value='single' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	before := len(pool.requests)
	if err := r.Report(context.Background()); err != nil || len(pool.requests) != before {
		t.Fatalf("single mode reported: %d requests %v", len(pool.requests)-before, err)
	}
}

// A stale grant cannot be made fresh by the request time. Resync to the remote seq, then ask
// again above it (also exercising PostgreSQL sequence resync after a restored database).
func TestReportResyncsStaleWithoutRenewingIt(t *testing.T) {
	r := poolStore(t)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	pool := &fakePool{answer: func(rep map[string]any) map[string]any {
		a := okAnswer(rep)
		a["result"] = "stale"
		a["seq"] = int64(100)
		return a
	}}
	r.Dir = suitedir.Client{Issuer: pool.serve(t).URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seq, ceiling, expiry := storedGrant(t, r, "org_a"); seq != 100 || ceiling != 0 || expiry != "" {
		t.Fatalf("stale grant stored: %d %d %q", seq, ceiling, expiry)
	}
	now = now.Add(time.Minute)
	pool.answer = okAnswer
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seq, ceiling, _ := storedGrant(t, r, "org_a"); seq <= 100 || ceiling != 5000 {
		t.Fatalf("resync: seq=%d ceiling=%d", seq, ceiling)
	}
}

func TestReportPausesOldGrantAndReleasesStoppedOrg(t *testing.T) {
	r := poolStore(t)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	pool := &fakePool{answer: okAnswer}
	r.Dir = suitedir.Client{Issuer: pool.serve(t).URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(451 * time.Second)
	pool.answer = func(rep map[string]any) map[string]any {
		if _, ceiling, expiry := storedGrant(t, r, "org_a"); ceiling != 0 || expiry != "" {
			t.Errorf("old headroom usable in flight: %d %q", ceiling, expiry)
		}
		return okAnswer(rep)
	}
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DB.Exec(`UPDATE orgs SET status='suspended' WHERE id='org_a'`); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	pool.answer = func(rep map[string]any) map[string]any {
		if rep["want_bytes"] != float64(0) {
			t.Errorf("stopped org requested headroom: %v", rep)
		}
		a := okAnswer(rep)
		a["ceiling_bytes"] = int64(0)
		return a
	}
	if err := r.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ceiling, _ := storedGrant(t, r, "org_a"); ceiling != 0 {
		t.Fatalf("stopped grant=%d", ceiling)
	}
}

// Authentication/transport and response-shape failures cannot create a grant.
func TestReportRejectsRedirectAndIncompleteGrant(t *testing.T) {
	for _, mode := range []string{"redirect", "incomplete", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			r := poolStore(t)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { t.Error("followed an issuer redirect") }))
			defer target.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
					return
				}
				if mode == "unauthorized" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"org_id": "org_a", "result": "ok", "seq": 1, "ceiling_bytes": 5000, "ttl_seconds": 900}}})
			}))
			defer srv.Close()
			r.Dir = suitedir.Client{Issuer: srv.URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
			if err := r.Report(context.Background()); err == nil {
				t.Fatal("untrusted answer accepted")
			}
			if _, ceiling, expiry := storedGrant(t, r, "org_a"); ceiling != 0 || expiry != "" {
				t.Fatalf("untrusted grant=%d %q", ceiling, expiry)
			}
		})
	}
}

// Unchanged charged usage is not a reason to retain an exhausted grant. Capacity freed in
// another app, or a resumed org, must be observed on the next one-minute report attempt.
func TestReportRenewsExhaustedGrantsEachMinute(t *testing.T) {
	for _, mode := range []string{"zero", "reservation-exhausts-positive-ceiling", "resume", "usable-unchanged"} {
		t.Run(mode, func(t *testing.T) {
			r := poolStore(t)
			if mode == "reservation-exhausts-positive-ceiling" {
				for _, q := range []string{
					`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_reserved','reserved','x','x',1,'t','t','org_a')`,
					`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('cnt_reserved','workbook','usr_reserved','t','t','org_a')`,
					`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES('ups_reserved','usr_reserved','cnt_reserved',64,64,'t','t','2099-01-01T00:00:00Z','org_a')`,
				} {
					if _, err := r.DB.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
			}
			now := time.Unix(1_800_000_000, 0)
			r.now = func() time.Time { return now }
			var free atomic.Int64
			if mode == "usable-unchanged" || mode == "resume" {
				free.Store(512)
			}
			pool := &fakePool{answer: func(rep map[string]any) map[string]any {
				if _, ceiling, expiry := storedGrant(t, r, "org_a"); ceiling != 0 || expiry != "" {
					t.Errorf("old grant remained usable in flight: %d %q", ceiling, expiry)
				}
				answer := okAnswer(rep)
				ceiling := int64(rep["used_bytes"].(float64)) + free.Load()
				if rep["want_bytes"] == float64(0) {
					ceiling = 0
				}
				answer["ceiling_bytes"] = ceiling
				return answer
			}}
			r.Dir = suitedir.Client{Issuer: pool.serve(t).URL, ClientID: "kynotes", ClientSecret: "suite-secret"}
			attempts := func() int { pool.mu.Lock(); defer pool.mu.Unlock(); return len(pool.requests) }
			report := func() {
				t.Helper()
				if err := r.Report(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			report()
			if attempts() != 1 {
				t.Fatalf("initial attempts=%d", attempts())
			}
			if mode == "usable-unchanged" {
				for _, elapsed := range []time.Duration{time.Minute, 449 * time.Second} {
					now = time.Unix(1_800_000_000, 0).Add(elapsed)
					report()
					if attempts() != 1 {
						t.Fatalf("usable grant renewed early at %v", elapsed)
					}
				}
				now = time.Unix(1_800_000_000, 0).Add(450 * time.Second)
				report()
				if attempts() != 2 {
					t.Fatal("usable grant did not renew at half TTL")
				}
				return
			}
			if mode == "resume" {
				if _, err := r.DB.Exec(`UPDATE orgs SET status='suspended' WHERE id='org_a'`); err != nil {
					t.Fatal(err)
				}
				now = now.Add(time.Minute)
				report()
				if _, ceiling, _ := storedGrant(t, r, "org_a"); ceiling != 0 {
					t.Fatalf("stopped org retained ceiling %d", ceiling)
				}
				if _, err := r.DB.Exec(`UPDATE orgs SET status='active' WHERE id='org_a'`); err != nil {
					t.Fatal(err)
				}
			}
			charged, err := storage.OrgChargedBytes(r.DB, r.DB, "org_a", "")
			if err != nil {
				t.Fatal(err)
			}
			if _, ceiling, _ := storedGrant(t, r, "org_a"); ceiling != charged {
				t.Fatalf("grant not exhausted: ceiling=%d charged=%d", ceiling, charged)
			}
			if refused, err := storage.PoolRefuses(r.DB, r.DB, "org_a", "", 1); err != nil || !refused {
				t.Fatalf("exhausted grant admitted growth: %v %v", refused, err)
			}
			before := attempts()
			free.Store(512) // another app frees space in the shared KyIdentity pool
			now = now.Add(59 * time.Second)
			report()
			if attempts() != before {
				t.Fatal("exhausted grant retried before one minute")
			}
			now = now.Add(time.Second)
			report()
			if attempts() != before+1 {
				t.Fatalf("exhausted grant did not renew on next minute: attempts=%d want=%d", attempts(), before+1)
			}
			if refused, err := storage.PoolRefuses(r.DB, r.DB, "org_a", "", 1); err != nil || refused {
				t.Fatalf("recovered grant unusable: %v %v", refused, err)
			}
		})
	}
}
