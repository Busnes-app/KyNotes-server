package httpapi

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
)

const officePeer = "203.0.113.5:41000" // inside 203.0.113.0/24

func exemptRouter(db *sql.DB, cfg config.Config) http.Handler {
	return NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true }, db, cfg)
}

// officeConfig lists the office in the configuration and lowers the sign-in rate so a
// handful of requests reaches the per-IP bucket's end.
func officeConfig(t *testing.T) (*sql.DB, config.Config) {
	db, cfg := setupTestDB(t)
	cfg.RateLimit.LoginPerMinute = 2
	cfg.RateLimit.ExemptNetworks = []string{"203.0.113.0/24"}
	return db, cfg
}

func send(h http.Handler, method, path, body, peer, forwarded string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = peer
	req.Header.Set("Content-Type", "application/json")
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("X-Kynotes-Key-Scheme", "shared-v2")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signIn answers with the code of one wrong-password login for a fresh username, so the
// per-account lockout never decides the outcome.
func signIn(h http.Handler, n int, peer, forwarded string) int {
	body := `{"username":"nobody-` + strconv.Itoa(n) + `","authSecret":"` + strings.Repeat("b", 64) + `"}`
	return send(h, "POST", "/api/v1/auth/login", body, peer, forwarded, nil, "").Code
}

// throttled reports whether n sign-ins from peer met the per-IP bucket.
func throttled(h http.Handler, n int, peer, forwarded string) bool {
	for i := 0; i < n; i++ {
		if signIn(h, int(time.Now().UnixNano())+i, peer, forwarded) == http.StatusTooManyRequests {
			return true
		}
	}
	return false
}

// An office goes past the per-IP sign-in buckets (login, login parameters, recovery);
// everyone else keeps them.
func TestExemptNetworkSkipsThePerIPSignInBuckets(t *testing.T) {
	db, cfg := officeConfig(t)
	h := exemptRouter(db, cfg)
	if throttled(h, 6, officePeer, "") {
		t.Fatal("the office met the per-IP login bucket")
	}
	if !throttled(h, 3, "198.51.100.9:41000", "") {
		t.Fatal("an address outside the office was not throttled")
	}
	for i := 0; i < 6; i++ {
		if code := send(h, "POST", "/api/v1/auth/login-params", `{"username":"anyone"}`, officePeer, "", nil, "").Code; code != 200 {
			t.Fatalf("office login-params %d answered %d", i, code)
		}
	}
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	recover := func(n int, peer string) int {
		body := `{"username":"lost-` + strconv.Itoa(n) + `","recoveryCode":"x","newAuthSecret":"` + strings.Repeat("1", 64) + `","newLoginSalt":"` + salt + `","iterations":600000}`
		return send(h, "POST", "/api/v1/auth/recover", body, peer, "", nil, "").Code
	}
	for i := 0; i < 3; i++ {
		if code := recover(i, officePeer); code != 401 {
			t.Fatalf("office recovery %d answered %d, want 401", i, code)
		}
	}
	recover(10, "198.51.100.10:1")
	recover(11, "198.51.100.10:1")
	if recover(12, "198.51.100.10:1") != http.StatusTooManyRequests {
		t.Fatal("recovery from outside the office was not throttled")
	}
}

// The exemption covers the per-IP bucket only: three wrong passwords for one account from
// the office still lock it there, and a recovery-code lockout holds the same way.
func TestExemptNetworkKeepsThePerAccountLockouts(t *testing.T) {
	db, cfg := officeConfig(t)
	h := exemptRouter(db, cfg)
	wrong := `{"username":"carol-office","authSecret":"` + strings.Repeat("b", 64) + `"}`
	for i := 0; i < 3; i++ {
		if code := send(h, "POST", "/api/v1/auth/login", wrong, officePeer, "", nil, "").Code; code != 401 {
			t.Fatalf("wrong password %d answered %d", i, code)
		}
	}
	if code := send(h, "POST", "/api/v1/auth/login", wrong, officePeer, "", nil, "").Code; code != http.StatusTooManyRequests {
		t.Fatalf("locked account answered %d from the office, want 429", code)
	}
	loginLockout.Success("carol-office\x00203.0.113.5")

	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	body := `{"username":"dave-office","recoveryCode":"x","newAuthSecret":"` + strings.Repeat("1", 64) + `","newLoginSalt":"` + salt + `","iterations":600000}`
	for i := 0; i < 3; i++ {
		send(h, "POST", "/api/v1/auth/recover", body, officePeer, "", nil, "")
	}
	if code := send(h, "POST", "/api/v1/auth/recover", body, officePeer, "", nil, "").Code; code != http.StatusTooManyRequests {
		t.Fatalf("locked recovery answered %d from the office, want 429", code)
	}
	recoveryLockout.Success("dave-office\x00203.0.113.5")
}

// A signed-in office client's credential routes keep their per-account bucket.
func TestExemptNetworkKeepsThePerAccountBucket(t *testing.T) {
	db, cfg := officeConfig(t)
	h := exemptRouter(db, cfg)
	adminID, _ := createAdminUser(t, db)
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	stepUp := `{"authSecret":"` + strings.Repeat("a", 64) + `"}`
	for i := 0; i < 2; i++ {
		if code := send(h, "POST", "/api/v1/auth/step-up", stepUp, officePeer, "", rec.Result().Cookies(), s.CSRF).Code; code != 204 {
			t.Fatalf("step-up %d answered %d", i, code)
		}
	}
	if code := send(h, "POST", "/api/v1/auth/step-up", stepUp, officePeer, "", rec.Result().Cookies(), s.CSRF).Code; code != http.StatusTooManyRequests {
		t.Fatalf("third step-up in a minute answered %d, want 429 from the account's bucket", code)
	}
}

// With no trusted proxy in front, X-Forwarded-For is the caller's own claim and buys nothing;
// behind a trusted proxy a client that prepends an office address is matched on the entry the
// proxy appended.
func TestForgedForwardedForCannotClaimAnExemptNetwork(t *testing.T) {
	db, cfg := officeConfig(t)
	if !throttled(exemptRouter(db, cfg), 3, "198.51.100.9:41000", "203.0.113.5") {
		t.Fatal("a forged X-Forwarded-For from an untrusted peer claimed the office")
	}
	cfg.Server.TrustedProxies = []string{"192.0.2.0/24"}
	h := exemptRouter(db, cfg)
	if throttled(h, 6, "192.0.2.7:41000", "203.0.113.5") {
		t.Fatal("the office behind the trusted proxy was throttled")
	}
	if !throttled(h, 3, "192.0.2.7:41000", "203.0.113.5, 198.51.100.9") {
		t.Fatal("a client behind the proxy claimed the office by prepending its address")
	}
}

func networks(t *testing.T, rec *httptest.ResponseRecorder) (stored, environment string, exempted float64) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out["networks"].(string), out["environment"].(string), out["exempted"].(float64)
}

// An administrator's list needs a step-up, takes effect at once, is stored canonically,
// audited, counted and still there after a restart; the configured list stays beside it.
func TestAdminSetsExemptNetworks(t *testing.T) {
	db, cfg := setupTestDB(t)
	cfg.RateLimit.LoginPerMinute = 2
	cfg.RateLimit.ExemptNetworks = []string{"198.18.7.0/24"}
	h := exemptRouter(db, cfg)
	adminID, _ := createAdminUser(t, db)
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	admin := rec.Result().Cookies()
	get := func(h http.Handler) *httptest.ResponseRecorder {
		return send(h, "GET", "/api/v1/admin/rate-limit-networks", "", "192.0.2.50:1", "", admin, "")
	}
	put := func(list string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"networks": list})
		return send(h, "PUT", "/api/v1/admin/rate-limit-networks", string(body), "192.0.2.50:1", "", admin, s.CSRF)
	}

	if stored, env, n := networks(t, get(h)); stored != "" || env != "198.18.7.0/24" || n != 0 {
		t.Fatalf("before: %q %q %v", stored, env, n)
	}
	if rr := put("203.0.113.0/24"); rr.Code != 403 || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Fatalf("save without step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := send(h, "POST", "/api/v1/auth/step-up", `{"authSecret":"`+strings.Repeat("a", 64)+`"}`, "192.0.2.50:1", "", admin, s.CSRF); rr.Code != 204 {
		t.Fatalf("step-up: %d %s", rr.Code, rr.Body)
	}
	if stored, _, _ := networks(t, put(" 203.0.113.77/24 , 2001:db8:1::/48")); stored != "203.0.113.0/24,2001:db8:1::/48" {
		t.Fatalf("stored %q, want the canonical list", stored)
	}
	if throttled(h, 4, officePeer, "") || throttled(h, 4, "198.18.7.50:1", "") {
		t.Fatal("a listed network was throttled")
	}
	if _, _, n := networks(t, get(h)); n != 8 {
		t.Fatalf("exempted = %v, want 8", n)
	}
	var reason, actor string
	if err := db.QueryRow(`SELECT reason_code,actor_user_id FROM audit_events WHERE event='admin.rate_limit_networks' ORDER BY rowid DESC LIMIT 1`).Scan(&reason, &actor); err != nil || actor != adminID || reason != `from="" to="203.0.113.0/24,2001:db8:1::/48"` {
		t.Fatalf("audit: %v %q %q", err, actor, reason)
	}

	// A restart loads the stored list.
	if throttled(exemptRouter(db, cfg), 4, officePeer, "") {
		t.Fatal("the stored list was not loaded at startup")
	}

	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/32", "office", "127.0.0.1", "203.0.113.0/24,nope"} {
		if rr := put(bad); rr.Code != 400 {
			t.Errorf("PUT %q answered %d, want 400", bad, rr.Code)
		}
	}
	if rr := put("10.0.0.0/8"); !strings.Contains(rr.Body.String(), "too broad") {
		t.Fatalf("refusal does not say why: %s", rr.Body)
	}
	if stored, _, _ := networks(t, get(h)); stored != "203.0.113.0/24,2001:db8:1::/48" {
		t.Fatalf("a refused list replaced the stored one: %q", stored)
	}
	if !throttled(h, 3, "10.9.9.9:1", "") {
		t.Fatal("an address in a refused range skipped the limit")
	}

	// Clearing restores the limit for the office; the configured network stays exempt.
	if stored, _, _ := networks(t, put("")); stored != "" {
		t.Fatalf("cleared list reads %q", stored)
	}
	if !throttled(h, 3, "203.0.113.200:1", "") {
		t.Fatal("a removed network is still exempt")
	}
	if throttled(h, 4, "198.18.7.51:1", "") {
		t.Fatal("clearing the admin list dropped the configured network")
	}
}

// Everyday accounts and anonymous callers neither read nor change the list.
func TestExemptNetworksAreAdminOnly(t *testing.T) {
	db, cfg := setupTestDB(t)
	h := exemptRouter(db, cfg)
	id, _ := ids.Mint("usr")
	hash, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,status,created_at,updated_at) VALUES(?,'eve',?,'salt',600000,'user','user','active','now','now')`, id, hash); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, id, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cookies []*http.Cookie
		csrf    string
	}{{nil, ""}, {rec.Result().Cookies(), s.CSRF}} {
		if code := send(h, "GET", "/api/v1/admin/rate-limit-networks", "", "192.0.2.1:1", "", c.cookies, "").Code; code != 401 && code != 403 {
			t.Errorf("GET answered %d", code)
		}
		if code := send(h, "PUT", "/api/v1/admin/rate-limit-networks", `{"networks":"203.0.113.0/24"}`, "192.0.2.1:1", "", c.cookies, c.csrf).Code; code != 401 && code != 403 {
			t.Errorf("PUT answered %d", code)
		}
	}
	if stored, _ := storedExemptNetworks(db); stored != "" {
		t.Fatalf("a non-administrator changed the list: %q", stored)
	}
}

// A stored list that no longer parses is dropped at startup, leaving the configured one.
func TestUnreadableStoredExemptNetworksAreIgnored(t *testing.T) {
	db, cfg := officeConfig(t)
	cfg.RateLimit.ExemptNetworks = []string{"198.18.7.0/24"}
	if _, err := db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,'now')`, exemptNetworksSetting, "203.0.113.0/24,10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	h := exemptRouter(db, cfg)
	if !throttled(h, 3, officePeer, "") {
		t.Fatal("a network from the unreadable stored list was exempt")
	}
	if throttled(h, 4, "198.18.7.9:1", "") {
		t.Fatal("the configured network lost its exemption")
	}
}
