package orgsync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
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
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('staff_org_id','org_staff','t')`,
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
	_ = r.DB.QueryRow(`SELECT seq,ceiling_bytes,expires_at FROM org_pool WHERE org_id=?`, org).Scan(&seq, &ceiling, &expires)
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
	pool.answer = func(rep map[string]any) map[string]any { return map[string]any{"org_id": rep["org_id"], "result": "unknown_org"} }
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
