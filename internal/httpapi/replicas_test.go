package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

func replicaDB(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	var schema string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	other, err := sql.Open("kynotespg", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	if err := other.Ping(); err != nil {
		t.Fatal(err)
	}
	return other
}

func TestReplicaSSOCallbackCrossesPoolsAndRemainsOneUse(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	f := newLogoutFixture(t)
	db2 := replicaDB(t, f.db)
	other := &logoutFixture{t: t, db: db2, cfg: f.cfg}
	other.restartRouter()
	toMultiMode(t, f.db, "org_staff")
	for _, org := range []string{storage.DefaultOrgID, "org_other"} {
		if _, err := f.db.Exec(`INSERT INTO orgs(id,status,home_region) VALUES(?,'active','local') ON CONFLICT(id) DO NOTHING`, org); err != nil {
			t.Fatal(err)
		}
	}
	request := func(org string) *http.Request {
		req := f.beginLogin("replica-user", "sid", time.Now())
		state := req.URL.Query().Get("state")
		f.mu.Lock()
		f.proofs[state]["org_id"] = org
		f.mu.Unlock()
		return req
	}
	req := request(storage.DefaultOrgID)
	if res := other.send(req); res.Code != 302 {
		t.Fatalf("cross-replica callback: %d %s", res.Code, res.Body.String())
	}
	if res := f.send(req); res.Code != 400 {
		t.Fatalf("replayed callback: %d %s", res.Code, res.Body.String())
	}
	if res := other.send(request("org_other")); res.Code != 403 || errorCode(t, res.Body.String()) != "org_mismatch" {
		t.Fatalf("wrong-org callback: %d %s", res.Code, res.Body.String())
	}
	// The durable PKCE payload contains no copied client or directory secret.
	settings := f.settings.Load()
	settings.ClientSecret = "environment-client-secret"
	settings.HMACSecret = strings.Repeat("h", 32)
	pending := &ssoTransactions{db: f.db, pending: make(map[string]ssoTransaction)}
	if err := pending.add("inspect", ssoTransaction{Settings: settings, Verifier: "verifier", Nonce: "nonce", Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := db2.QueryRow(`SELECT payload FROM replica_logins WHERE state_hash=?`, storage.StateHash("inspect")).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), settings.ClientSecret) || strings.Contains(string(payload), settings.HMACSecret) {
		t.Fatal("environment secrets copied into PKCE state")
	}
	if _, err := f.db.Exec(`DROP TABLE replica_logins`); err != nil {
		t.Fatal(err)
	}
	if err := pending.add("must-not-fallback", ssoTransaction{Expires: time.Now().Add(time.Minute)}); err == nil || len(pending.pending) != 0 {
		t.Fatal("failed shared state fell back to memory")
	}
}

func TestReplicaPresenceMembershipAndRateLimits(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	p := newPairClient(t, strings.Repeat("p", 32))
	db2 := replicaDB(t, p.db)
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	outsider := p.addUserInOrg(t, "outsider", "org_other")
	cfg := config.Defaults()
	cfg.RateLimit.LoginPerMinute = 2
	a, b := http.NewServeMux(), http.NewServeMux()
	PushRoutes(a, p.db)
	PushRoutes(b, db2)
	toMultiMode(t, p.db, "org_staff")
	send := func(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		u, _ := url.Parse(p.url)
		for _, cookie := range p.hc.Jar.Cookies(u) {
			req.AddCookie(cookie)
			if cookie.Name == "csrf_token" {
				req.Header.Set("X-CSRF-Token", cookie.Value)
			}
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}
	if res := send(a, "POST", "/api/v1/presence", `{"containerId":`+quote(cid)+`,"state":"editing"}`); res.Code != 204 {
		t.Fatalf("presence: %d %s", res.Code, res.Body.String())
	}
	res := send(b, "GET", "/api/v1/presence?containerId="+cid, "")
	var got []map[string]string
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &got) != nil || len(got) != 1 || got[0]["userId"] != pairUser {
		t.Fatalf("presence missing on second pool: %d %s", res.Code, res.Body.String())
	}
	if _, err := db2.Exec(`INSERT INTO replica_presence(user_id,container_id,state,expires_at) VALUES(?,?,?,9999999999)`, outsider.id, cid, "editing"); err == nil {
		t.Fatal("cross-org presence accepted")
	}
	if _, err := p.db.Exec(`UPDATE memberships SET revoked_at='gone' WHERE user_id=? AND container_id=?`, pairUser, cid); err != nil {
		t.Fatal(err)
	}
	if res := send(b, "GET", "/api/v1/presence?containerId="+cid, ""); res.Code != 404 {
		t.Fatalf("removed member sees presence: %d", res.Code)
	}
	// Two fresh middleware instances cannot each spend a private sign-in burst.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	ra, rb := rateLimitMiddleware(cfg, p.db, handler), rateLimitMiddleware(cfg, db2, handler)
	for i, h := range []http.Handler{ra, rb, ra} {
		res := send(h, "POST", "/api/v1/auth/login-params", `{}`)
		want := 204
		if i == 2 {
			want = 429
		}
		if res.Code != want {
			t.Fatalf("shared rate request %d: %d %s", i, res.Code, res.Body.String())
		}
	}
}

func TestReplicaReminderClaimExcludesOtherWorkerAndProtectsReschedule(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	p, _, sender := reminderServer(t)
	db2 := replicaDB(t, p.db)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var hits atomic.Int32
	ps := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(201)
	}))
	defer ps.Close()
	sender.Client = webpush.NewClient(ps.Client().Transport)
	sender.Allow = func(endpoint string) bool { return strings.HasPrefix(endpoint, ps.URL+"/") }
	addSubscription(t, p.db, p.id, "wps_claim", ps.URL+"/push")
	now := time.Now().UTC().Truncate(time.Second)
	id := strings.Repeat("c", 26)
	addReminder(t, p.db, p.id, id, now)
	toMultiMode(t, p.db, "org_staff")
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- sender.Fire(ctx, p.db, now) }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("reminder never sent")
	}
	if err := sender.Fire(ctx, db2, now); err != nil {
		close(release)
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		close(release)
		t.Fatalf("duplicate reminder: %d", hits.Load())
	}
	// The scheduling UPDATE clears the old claim; old completion must keep the new due time.
	if _, err := db2.Exec(`UPDATE reminders SET at=? WHERE id=?`, now.Add(time.Hour).Format(time.RFC3339), id); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if count(t, p.db, `SELECT count(*) FROM reminders WHERE id=? AND claim_token='' AND claimed_until=0`, id) != 1 {
		t.Fatal("old worker deleted rescheduled reminder")
	}
}

func TestReplicaReadinessPingsAndDrainsWithoutChangingLiveness(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	p := newPairClient(t, strings.Repeat("p", 32))
	db2 := replicaDB(t, p.db)
	var draining atomic.Bool
	h := NewRouter(logging.New(io.Discard, "info", "json"), config.Defaults().Server.MaxRequestBytes, func() bool { return !draining.Load() }, db2, config.Defaults())
	probe := func(path string) int {
		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest("GET", path, nil))
		return res.Code
	}
	if probe("/readyz") != 200 {
		t.Fatal("healthy replica not ready")
	}
	draining.Store(true)
	if probe("/readyz") != 503 || probe("/livez") != 200 {
		t.Fatal("drain did not immediately remove readiness only")
	}
	draining.Store(false)
	db2.Close()
	time.Sleep(1100 * time.Millisecond) // expire the documented one-second ping cache
	if probe("/readyz") != 503 || probe("/livez") != 200 {
		t.Fatal("database loss did not remove readiness only")
	}
}
