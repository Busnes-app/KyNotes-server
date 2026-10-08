package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
)

// liveCookies keeps the cookies a login response set (not the ones it cleared).
func liveCookies(res *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range res.Result().Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			out = append(out, c)
		}
	}
	return out
}

// userReauthFixture signs bob in through SSO with no app role and mounts POST /user-action behind
// RequireUserActionStepUp and POST /action behind the admin RequireStepUp.
func userReauthFixture(t *testing.T) (*logoutFixture, []*http.Cookie) {
	f := newLogoutFixture(t)
	login := roleCallback(f, "bob", nil, "")
	if login.Code != 302 {
		t.Fatal(login.Body.String())
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux := f.router.(*http.ServeMux)
	mux.Handle("POST /user-action", auth.RequireUserActionStepUp(f.db, ok))
	mux.Handle("POST /action", auth.RequireStepUp(f.db, ok))
	return f, liveCookies(login)
}

func TestSSOUserStepUpNeedsNoAdminRole(t *testing.T) {
	f, cookies := userReauthFixture(t)
	// The admin route stays closed to a non-admin: no challenge is even offered.
	if r := reauthAction(f, cookies, "", "/action", `{"x":1}`); r.Code != 403 || strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("a non-admin was offered an admin challenge", r.Code, r.Body.String())
	}
	id, callback := reauthStartAt(f, cookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal("user challenge refused without an admin role", res.Code, res.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":2}`); r.Code != 403 {
		t.Fatal("a grant for one body admitted another", r.Code)
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("grant reused", r.Code)
	}
}

func TestSSOStepUpScopeIsBoundToTheGrant(t *testing.T) {
	f, cookies := reauthFixture(t)
	// An admin challenge answered without kynotes.admin is rejected at the callback.
	rejected, callback := reauthStartAt(f, cookies, "alice", "/action", `{"target":1}`, nil)
	if res := f.send(callback); res.Code != 403 {
		t.Fatal("admin challenge verified without the admin role", res.Code)
	}
	// The browser cancels an unverified challenge (web/src/reauth.ts) before the next action.
	if res := f.send(withCookies(httptest.NewRequest("DELETE", "/api/v1/auth/oidc/step-up/"+rejected, nil), cookies)); res.Code != 204 {
		t.Fatal("cancel", res.Code)
	}
	// A verified admin grant relabelled as a user grant no longer opens the admin route.
	id, callback := reauthStart(f, cookies)
	if res := f.send(callback); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := f.db.Exec(`UPDATE sso_stepup SET scope='user' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(f, cookies, id, "/action", `{"target":1}`); r.Code != 403 {
		t.Fatal("a user-scope grant opened an admin route", r.Code)
	}
	// And a user route refuses a grant recorded as admin.
	g, userCookies := userReauthFixture(t)
	uid, ucb := reauthStartAt(g, userCookies, "bob", "/user-action", `{"x":1}`, nil)
	if res := g.send(ucb); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if _, err := g.db.Exec(`UPDATE sso_stepup SET scope='admin' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(g, userCookies, uid, "/user-action", `{"x":1}`); r.Code != 403 {
		t.Fatal("an admin-scope grant opened a user route", r.Code)
	}
}

func TestUserActionStepUpNeedsFreshLocalProof(t *testing.T) {
	f, cookies := userReauthFixture(t)
	// The same session as a local one: the middleware itself refuses it until a fresh password step-up.
	if _, err := f.db.Exec(`UPDATE sessions SET sso_issuer='',sso_client_id='',sso_subject=''`); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":1}`); r.Code != 403 || !strings.Contains(r.Body.String(), `"step_up_required"`) {
		t.Fatal("a local session without a step-up passed", r.Code, r.Body.String())
	}
	if _, err := f.db.Exec(`UPDATE sessions SET stepup_at=?`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal("a fresh local step-up was refused", r.Code, r.Body.String())
	}
}

func TestSSOAdminStepUpRechecksLocalAdminAtVerification(t *testing.T) {
	f, cookies := reauthFixture(t)
	_, callback := reauthStart(f, cookies)
	// Demoted between challenge and proof: a fresh kynotes.admin claim alone does not verify it.
	if _, err := f.db.Exec(`UPDATE users SET role='user' WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	if res := f.send(callback); res.Code != 403 {
		t.Fatal("a demoted admin verified an admin challenge", res.Code)
	}
}

func deviceOnlyBody(pub []byte) string {
	return `{"publicKey":` + quote(base64.StdEncoding.EncodeToString(pub)) + `,"wrapAlg":"none"}`
}

// ssoPerson signs subject in through the fixture's IdP (no app role): its cookies and user ID.
func ssoPerson(f *logoutFixture, subject, sid string) ([]*http.Cookie, string) {
	f.t.Helper()
	res := f.send(f.beginLogin(subject, sid, time.Now()))
	if res.Code != 302 {
		f.t.Fatalf("login %s: %d %s", subject, res.Code, res.Body.String())
	}
	var id string
	if err := f.db.QueryRow(`SELECT id FROM users WHERE username=?`, subject).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return liveCookies(res), id
}

// ssoDo sends method path body as an SSO session. When the route asks for a KySignOn confirmation it
// completes one for subject (no app role) and retries the identical request with the grant.
func ssoDo(f *logoutFixture, cookies []*http.Cookie, subject, method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	send := func(grant string) *httptest.ResponseRecorder {
		req := withCookies(httptest.NewRequest(method, path, strings.NewReader(body)), cookies)
		req.Header.Set("Content-Type", "application/json")
		if grant != "" {
			req.Header.Set("X-Kynotes-Step-Up", grant)
		}
		return f.send(req)
	}
	first := send("")
	var detail struct {
		Error struct{ Code, Challenge string }
	}
	if first.Code != 403 || json.Unmarshal(first.Body.Bytes(), &detail) != nil || detail.Error.Code != "sso_step_up_required" {
		return first
	}
	start := f.send(withCookies(httptest.NewRequest("POST", "/api/v1/auth/oidc/step-up", strings.NewReader(`{"challenge":"`+detail.Error.Challenge+`"}`)), cookies))
	var begun struct{ URL string }
	if start.Code != 200 || json.Unmarshal(start.Body.Bytes(), &begun) != nil {
		f.t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	dest, err := url.Parse(begun.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := dest.Query()
	state, now := q.Get("state"), time.Now().Unix()
	f.mu.Lock()
	f.proofs[state] = map[string]any{"iss": f.issuer.URL, "aud": "kynotes", "sub": subject, "sid": "fresh-proof", "iat": now, "exp": now + 3600, "nonce": q.Get("nonce"), "auth_time": now, "acr": "urn:kysignon:acr:password", "amr": []string{"pwd"}}
	f.mu.Unlock()
	callback := withCookies(httptest.NewRequest("GET", "/api/v1/auth/oidc/callback?code="+state+"&state="+state, nil), cookies)
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	if res := f.send(callback); res.Code != 200 {
		f.t.Fatalf("callback: %d %s", res.Code, res.Body.String())
	}
	return send(detail.Error.Challenge)
}

func TestSSOSessionCreatesDeviceOnlyIdentity(t *testing.T) {
	f := newLogoutFixture(t)
	cookies, bob := ssoPerson(f, "bob", "bob-1")
	// An administrator-known password refuses only password proofs; a KySignOn confirmation still creates.
	if _, err := f.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, bob); err != nil {
		t.Fatal(err)
	}
	plain := withCookies(httptest.NewRequest("PUT", "/api/v1/me/identity", strings.NewReader(deviceOnlyBody(identityPub))), cookies)
	plain.Header.Set("Content-Type", "application/json")
	if r := f.send(plain); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("created without a KySignOn confirmation", r.Code, r.Body.String())
	}
	put := func(body string) int { return ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", body).Code }
	// A password wrap from a session that proved no password, or a wrapped key beside "none": refused.
	if code := put(string(identityBody(identityPub, identityWrapped))); code != 400 {
		t.Fatal("SSO session stored a password wrap", code)
	}
	if code := put(`{"publicKey":` + quote(base64.StdEncoding.EncodeToString(identityPub)) + `,"wrapAlg":"none","wrappedPrivateKey":` + quote(base64.StdEncoding.EncodeToString(identityWrapped)) + `}`); code != 400 {
		t.Fatal("device-only identity carried a server copy", code)
	}
	if code := put(deviceOnlyBody(identityPub)); code != 200 {
		t.Fatal("device-only create", code)
	}
	var alg string
	var wrapped []byte
	if err := f.db.QueryRow(`SELECT wrap_alg,wrapped_private_key FROM user_identities WHERE user_id=?`, bob).Scan(&alg, &wrapped); err != nil || alg != "none" || len(wrapped) != 0 {
		t.Fatalf("stored %q %d bytes: %v", alg, len(wrapped), err)
	}
	// The audit names the wrap and the KySignOn grant that created it (decision 4's trace).
	var reason string
	if err := f.db.QueryRow(`SELECT reason_code FROM audit_events WHERE event='identity.create' AND user_id=?`, bob).Scan(&reason); err != nil || !strings.HasPrefix(reason, "wrap=none,proof=sso:rea_") {
		t.Fatalf("identity.create reason %q: %v", reason, err)
	}
	get := f.send(withCookies(httptest.NewRequest("GET", "/api/v1/me/identity", nil), cookies))
	if !strings.Contains(get.Body.String(), `"wrapAlg":"none"`) || strings.Contains(get.Body.String(), "wrappedPrivateKey") {
		t.Fatal("GET /me/identity", get.Body.String())
	}
}

func TestDeviceOnlyIdentityIsNeverWrappedByAPassword(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.stepUp(t)
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", []byte(deviceOnlyBody(identityPub)), true, false)); code != http.StatusBadRequest {
		t.Fatal("a password session created a device-only identity", code)
	}
	id := p.createIdentity(t)
	var reason string
	if err := p.db.QueryRow(`SELECT reason_code FROM audit_events WHERE event='identity.create'`).Scan(&reason); err != nil || reason != "wrap=aes-256-gcm,proof=password" {
		t.Fatalf("identity.create reason %q: %v", reason, err)
	}
	// As if created from a single sign-on session: no server copy.
	if _, err := p.db.Exec(`UPDATE user_identities SET wrap_alg='none',wrapped_private_key=X'' WHERE user_id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, p.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != 200 || !strings.Contains(body, `"wrapAlg":"none"`) || strings.Contains(body, base64.StdEncoding.EncodeToString(identityWrapped)) {
		t.Fatalf("login identity: %d %s", code, body)
	}
	change := func(rewrap bool) (int, string) {
		body := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":100000`
		if rewrap {
			body += `,"wrappedIdentityKey":` + quote(base64.StdEncoding.EncodeToString(identityWrapped)) + `,"identityDeviceId":` + quote(id)
		}
		return status(t, p.do(t, http.MethodPost, "/api/v1/auth/password", []byte(body+`}`), true, false))
	}
	if code, body := change(true); code != http.StatusConflict || !strings.Contains(body, "identity_rewrap_required") {
		t.Fatalf("a password wrapped a device-only identity: %d %s", code, body)
	}
	if code, body := change(false); code != http.StatusNoContent {
		t.Fatalf("password change without a re-wrap: %d %s", code, body)
	}
	var alg string
	if err := p.db.QueryRow(`SELECT wrap_alg FROM user_identities WHERE user_id=?`, pairUser).Scan(&alg); err != nil || alg != "none" {
		t.Fatal(alg, err)
	}
}

// ssoTeam creates bob's device-only identity and a team container bob owns at generation 1.
func ssoTeam(t *testing.T) (f *logoutFixture, cookies []*http.Cookie, bob, device, cid string) {
	f = newLogoutFixture(t)
	cookies, bob = ssoPerson(f, "bob", "bob-1")
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", deviceOnlyBody(identityPub)); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	if err := f.db.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, bob).Scan(&device); err != nil {
		t.Fatal(err)
	}
	cid = mint(t, "cnt")
	if _, err := f.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,team_id,created_at,updated_at) VALUES(?,'team',?,'','now','now')`, cid, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'owner','now')`, mint(t, "mem"), cid, bob); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSSOStewardSharesKeysAfterActionStepUp(t *testing.T) {
	f, cookies, _, device, cid := ssoTeam(t)
	rotate := "/api/v1/containers/" + cid + "/key-rotations"
	body := string(rotationBody(1, envJSON(device, 2, 1)))
	plain := withCookies(httptest.NewRequest("POST", rotate, strings.NewReader(body)), cookies)
	plain.Header.Set("Content-Type", "application/json")
	if r := f.send(plain); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("rotated without a KySignOn confirmation", r.Code, r.Body.String())
	}
	if r := ssoDo(f, cookies, "bob", "POST", rotate, body); r.Code != 200 {
		t.Fatal("SSO steward rotation", r.Code, r.Body.String())
	}
	// Re-wrapping its own identity envelope takes the same confirmation.
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/containers/"+cid+"/envelopes", string(envelopesBody(envJSON(device, 2, 2)))); r.Code != 204 {
		t.Fatal("SSO envelope write", r.Code, r.Body.String())
	}
}

func TestSSOGrantIsRecheckedInTheWriteTransaction(t *testing.T) {
	f, cookies, bob, device, cid := ssoTeam(t)
	// The session dies in the very transaction that consumes the grant.
	if _, err := f.db.Exec(`CREATE TRIGGER revoke_on_consume AFTER INSERT ON audit_events WHEN NEW.event='auth.sso_step_up.consume' BEGIN UPDATE sessions SET revoked_at='revoked' WHERE user_id='` + bob + `'; END`); err != nil {
		t.Fatal(err)
	}
	if r := ssoDo(f, cookies, "bob", "POST", "/api/v1/containers/"+cid+"/key-rotations", string(rotationBody(1, envJSON(device, 2, 1)))); r.Code == 200 {
		t.Fatal("a session revoked after its grant still rotated")
	}
	var generation int
	if err := f.db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation); err != nil || generation != 1 {
		t.Fatal(generation, err)
	}
}

// After an administrator reset, the SSO user's device-only identity must not be driven by the
// password the administrator knows: every local action step-up answers 409 until the user's own change.
func TestAdminKnownPasswordCannotActForDeviceOnlyIdentity(t *testing.T) {
	f, _, bob, device, cid := ssoTeam(t)
	secret := strings.Repeat("a", 64)
	hash, err := auth.HashAuthSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE users SET auth_secret_hash=?,password_admin_known=1 WHERE id=?`, hash, bob); err != nil {
		t.Fatal(err)
	}
	login := f.send(httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"bob","authSecret":"`+secret+`"}`)))
	if login.Code != 200 {
		t.Fatal("local login", login.Code, login.Body.String())
	}
	local := liveCookies(login)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := withCookies(httptest.NewRequest(method, path, strings.NewReader(body)), local)
		req.Header.Set("Content-Type", "application/json")
		return f.send(req)
	}
	if r := do("POST", "/api/v1/auth/step-up", `{"authSecret":"`+secret+`"}`); r.Code != 200 && r.Code != 204 {
		t.Fatal("step-up", r.Code, r.Body.String())
	}
	invitee := mint(t, "usr")
	if _, err := f.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,'carol','x','x',1,'now','now')`, invitee); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*httptest.ResponseRecorder{
		"rotation":   do("POST", "/api/v1/containers/"+cid+"/key-rotations", string(rotationBody(1, envJSON(device, 2, 1)))),
		"envelopes":  do("PUT", "/api/v1/containers/"+cid+"/envelopes", string(envelopesBody(envJSON(device, 1, 3)))),
		"invitation": do("POST", "/api/v1/containers/"+cid+"/invitations", `{"inviteeId":`+quote(invitee)+`,"role":"editor","envelopes":[{"containerId":`+quote(cid)+`,"deviceId":`+quote(device)+`,"keyGeneration":1,"alg":"x25519-hkdf-sha256-chacha20poly1305","envelope":"AA=="}]}`),
	} {
		if r.Code != 409 || !strings.Contains(r.Body.String(), "password_change_required") {
			t.Errorf("%s with an administrator-known password: %d %s", name, r.Code, r.Body.String())
		}
	}
	var generation int
	if err := f.db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&generation); err != nil || generation != 1 {
		t.Fatal(generation, err)
	}
}

func TestSSOChallengeCreationIsRateLimitedPerAccount(t *testing.T) {
	f, cookies := userReauthFixture(t)
	cfg := config.Defaults()
	f.router = rateLimitMiddleware(cfg, f.db, f.router)
	for i := 0; i < cfg.RateLimit.LoginPerMinute; i++ {
		if r := reauthAction(f, cookies, "", "/user-action", `{"x":1}`); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
			t.Fatal(i, r.Code, r.Body.String())
		}
	}
	r := reauthAction(f, cookies, "", "/user-action", `{"x":1}`)
	if r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatal("challenge minted past the account's bucket", r.Code, r.Body.String())
	}
	var audits int
	if err := f.db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='auth.sso_step_up.start'`).Scan(&audits); err != nil || audits != cfg.RateLimit.LoginPerMinute {
		t.Fatal("start audits", audits, err)
	}
}

func TestBackgroundChallengeLeavesAStartedConfirmationAlone(t *testing.T) {
	f, cookies := userReauthFixture(t)
	id, callback := reauthStartAt(f, cookies, "bob", "/user-action", `{"x":1}`, nil)
	// A background write while the user is in KySignOn: refused, the confirmation untouched.
	r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`)
	var pending struct {
		Error struct{ Code, Challenge string }
	}
	if r.Code != 409 || json.Unmarshal(r.Body.Bytes(), &pending) != nil || pending.Error.Code != "step_up_pending" || pending.Error.Challenge != id {
		t.Fatal("background challenge during a confirmation must name the pending one", r.Code, r.Body.String())
	}
	if res := f.send(callback); res.Code != 200 {
		t.Fatal("confirmation lost to a background write", res.Code, res.Body.String())
	}
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`); r.Code != 409 {
		t.Fatal("a verified grant was replaced before use", r.Code)
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("no new challenge after the grant was used", r.Code, r.Body.String())
	}
}

func TestPendingRefusalSpendsNoChallengeBudget(t *testing.T) {
	f, cookies := userReauthFixture(t)
	cfg := config.Defaults()
	cfg.RateLimit.LoginPerMinute = 2
	f.router = rateLimitMiddleware(cfg, f.db, f.router)
	id, callback := reauthStartAt(f, cookies, "bob", "/user-action", `{"x":1}`, nil) // one token
	for i := 0; i < 5; i++ {
		if r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`); r.Code != 409 {
			t.Fatal("refused background write", i, r.Code, r.Body.String())
		}
	}
	if res := f.send(callback); res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if r := reauthAction(f, cookies, id, "/user-action", `{"x":1}`); r.Code != 204 {
		t.Fatal(r.Code, r.Body.String())
	}
	// The second token is still there: the refusals did not drain it.
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("pending refusals spent the challenge budget", r.Code, r.Body.String())
	}
}

// firstLinkVector is links[0] of the shared vector file: the server must accept its commitment.
func firstLinkVector(t *testing.T) (commitment, newcomerKey, approverKey []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/protocol/link_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Links []struct{ Commitment, NewcomerPublicKey, ApproverPublicKey string } `json:"links"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	v := file.Links[0]
	return decode(v.Commitment), decode(v.NewcomerPublicKey), decode(v.ApproverPublicKey)
}

// secondSession signs the pair user in again in a fresh cookie jar: another browser of one account.
func (p *pairClient) secondSession(t *testing.T) *pairClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	q := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url}
	if code, body := status(t, q.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("second login=%d %s", code, body)
	}
	return q
}

func linkPath(id, suffix string) string { return "/api/v1/me/link-requests/" + id + suffix }

func createLinkRequest(t *testing.T, p *pairClient, commitment []byte) string {
	t.Helper()
	code, body := status(t, p.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false))
	var out struct{ ID, ExpiresAt string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil || !strings.HasPrefix(out.ID, "lnk_") || out.ExpiresAt == "" {
		t.Fatalf("create=%d %s", code, body)
	}
	return out.ID
}

// openLink: a request from a second session of pair, claimed by the first and revealed.
func openLink(t *testing.T) (trusted, newcomer *pairClient, id string) {
	t.Helper()
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted = newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer = trusted.secondSession(t)
	id = createLinkRequest(t, newcomer, commitment)
	if code, body := status(t, trusted.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("claim=%d %s", code, body)
	}
	if code, body := status(t, newcomer.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("reveal=%d %s", code, body)
	}
	return
}

// audited counts successful audit rows of event.
func audited(t *testing.T, p *pairClient, event string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event=? AND outcome='success'`, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// refused counts denied audit rows of event with reason.
func refused(t *testing.T, p *pairClient, event, reason string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event=? AND outcome='denied' AND reason_code=?`, event, reason).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// auditLeaks returns any audit value carrying one of secrets, in base64 or hex.
func auditLeaks(t *testing.T, p *pairClient, secrets ...[]byte) string {
	t.Helper()
	rows, err := p.db.Query(`SELECT event||' '||container_id||' '||object_id||' '||reason_code||' '||request_id FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if strings.Contains(row, b64(s)) || strings.Contains(row, hex.EncodeToString(s)) || strings.Contains(row, base64.RawURLEncoding.EncodeToString(s)) {
				return row
			}
		}
	}
	return ""
}

func TestLinkRelayHandsOverOnlyPublicKeys(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer := trusted.secondSession(t)
	id := createLinkRequest(t, newcomer, commitment)
	get := func(p *pairClient, path string) (int, string) {
		return status(t, p.do(t, http.MethodGet, path, nil, false, false))
	}
	// The newcomer does not see its own request in the approver list; the trusted session does.
	if _, body := get(newcomer, "/api/v1/me/link-requests"); strings.TrimSpace(body) != "[]" {
		t.Fatal("newcomer listed its own request", body)
	}
	if _, body := get(trusted, "/api/v1/me/link-requests"); !strings.Contains(body, id) || !strings.Contains(body, b64(commitment)) || !strings.Contains(body, `"claimed":false`) || !strings.Contains(body, `"newcomerKey":""`) {
		t.Fatal("trusted list", body)
	}
	claim := func(p *pairClient) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false))
		return code
	}
	if claim(newcomer) != http.StatusNotFound {
		t.Fatal("the newcomer claimed its own request")
	}
	if claim(trusted) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if claim(trusted) != http.StatusNotFound {
		t.Fatal("claimed twice")
	}
	third := trusted.secondSession(t)
	if claim(third) != http.StatusNotFound {
		t.Fatal("a second approver claimed a claimed request")
	}
	if _, body := get(third, "/api/v1/me/link-requests"); strings.Contains(body, id) {
		t.Fatal("another session lists a request claimed by someone else", body)
	}
	// The newcomer learns the approver key and nothing else yet.
	if code, body := get(newcomer, linkPath(id, "")); code != 200 || !strings.Contains(body, `"state":"claimed"`) || !strings.Contains(body, b64(approverKey)) || strings.Contains(body, "bundle") {
		t.Fatal("newcomer state", code, body)
	}
	reveal := func(p *pairClient) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false))
		return code
	}
	if reveal(trusted) != http.StatusNotFound {
		t.Fatal("the approver revealed")
	}
	if reveal(newcomer) != http.StatusNoContent || reveal(newcomer) != http.StatusNotFound {
		t.Fatal("reveal is not once")
	}
	if _, body := get(trusted, "/api/v1/me/link-requests"); !strings.Contains(body, b64(newcomerKey)) || !strings.Contains(body, `"claimed":true`) {
		t.Fatal("revealed key not listed to its approver", body)
	}
	for _, event := range []string{"identity.link.request", "identity.link.claim", "identity.link.reveal"} {
		if audited(t, trusted, event) != 1 {
			t.Fatal("audit", event)
		}
	}
}

func TestLinkRequestRefusals(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	newcomer := trusted.secondSession(t)
	create := func(p *pairClient, value []byte, csrf bool) int {
		code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(value))+`}`), csrf, false))
		return code
	}
	if create(newcomer, commitment, true) != http.StatusNotFound {
		t.Fatal("a link request for an account with no identity")
	}
	trusted.createIdentity(t)
	if create(newcomer, commitment[:31], true) != http.StatusBadRequest || create(newcomer, commitment, false) != http.StatusForbidden {
		t.Fatal("malformed commitment or missing CSRF accepted")
	}
	// Another account sees none of it, by any route.
	other := trusted.addUser(t, "other")
	id := createLinkRequest(t, newcomer, commitment)
	for _, call := range [][2]string{{http.MethodPost, "/claim"}, {http.MethodPost, "/reveal"}, {http.MethodGet, ""}, {http.MethodDelete, ""}} {
		if code, _ := status(t, other.do(t, call[0], linkPath(id, call[1]), []byte(`{"approverKey":`+quote(b64(approverKey))+`,"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNotFound {
			t.Fatal("another account reached", call, code)
		}
	}
	// Expired requests are gone for everyone.
	if _, err := trusted.db.Exec(`UPDATE link_requests SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	claim := func(p *pairClient, id string) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false))
		return code
	}
	if claim(trusted, id) != http.StatusNotFound {
		t.Fatal("expired request claimed")
	}
	if code, _ := status(t, newcomer.do(t, http.MethodGet, linkPath(id, ""), nil, false, false)); code != http.StatusNotFound {
		t.Fatal("expired request collected")
	}
	// A key that does not match the commitment ends the attempt.
	id = createLinkRequest(t, newcomer, commitment)
	if claim(trusted, id) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if code, _ := status(t, newcomer.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusBadRequest {
		t.Fatal("a key that does not match its commitment was revealed", code)
	}
	var rows int
	if err := trusted.db.QueryRow(`SELECT COUNT(*) FROM link_requests WHERE id=?`, id).Scan(&rows); err != nil || rows != 0 || refused(t, trusted, "identity.link.refuse", "commitment") != 1 {
		t.Fatal("refused attempt kept", rows, err)
	}
	// Both sessions must be live: a revoked newcomer cannot be claimed, a revoked approver cannot be revealed to.
	approver := trusted.secondSession(t)
	id = createLinkRequest(t, newcomer, commitment)
	if _, err := trusted.db.Exec(`UPDATE sessions SET revoked_at='x' WHERE id=(SELECT newcomer_session_id FROM link_requests WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	if claim(approver, id) != http.StatusNotFound {
		t.Fatal("claimed for a revoked newcomer session")
	}
	fresh := trusted.secondSession(t)
	id = createLinkRequest(t, fresh, commitment)
	if claim(approver, id) != http.StatusNoContent {
		t.Fatal("claim")
	}
	if _, err := trusted.db.Exec(`UPDATE sessions SET revoked_at='x' WHERE id=(SELECT approver_session_id FROM link_requests WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, fresh.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(newcomerKey))+`}`), true, false)); code != http.StatusNotFound {
		t.Fatal("revealed to a revoked approver session", code)
	}
	// At most three live requests per account; the same browser restarting replaces its own.
	if _, err := trusted.db.Exec(`DELETE FROM link_requests`); err != nil {
		t.Fatal(err)
	}
	extra := trusted.secondSession(t)
	for _, p := range []*pairClient{trusted, fresh, extra} {
		createLinkRequest(t, p, commitment)
	}
	if code, body := status(t, trusted.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code != http.StatusOK {
		t.Fatal("the same browser restarting was refused", code, body)
	}
	fourth := trusted.secondSession(t)
	if code, body := status(t, fourth.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code != http.StatusConflict || !strings.Contains(body, "already_exists") {
		t.Fatal("a fourth live request", code, body)
	}
	// Any session of the account cancels ("Not me"); once.
	id = createLinkRequest(t, fresh, commitment)
	if code, _ := status(t, trusted.do(t, http.MethodDelete, linkPath(id, ""), nil, true, false)); code != http.StatusNoContent {
		t.Fatal("cancel")
	}
	if code, _ := status(t, trusted.do(t, http.MethodDelete, linkPath(id, ""), nil, true, false)); code != http.StatusNotFound || audited(t, trusted, "identity.link.cancel") != 1 {
		t.Fatal("cancelled twice")
	}
	// Device credentials never reach the relay.
	trusted.deviceID, trusted.deviceSecret, _ = trusted.register(t, trusted.mintToken(t), bytes.Repeat([]byte{7}, 32))
	if code, _ := status(t, trusted.doDeviceOnly(t, http.MethodGet, "/api/v1/me/link-requests", nil)); code != http.StatusUnauthorized {
		t.Fatal("device credential listed link requests", code)
	}
}

func TestLinkCreationIsRateLimitedPerAccount(t *testing.T) {
	commitment, _, _ := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	for i := 0; i < 20; i++ { // config.Defaults: pairing_per_hour 20
		createLinkRequest(t, trusted, commitment)
	}
	res := trusted.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)
	if code, body := status(t, res); code != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "180" { // refills 20 an hour
		t.Fatal("21st link request in an hour", code, body, res.Header.Get("Retry-After"))
	}
	other := trusted.addUser(t, "other")
	if code, _ := status(t, other.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false)); code == http.StatusTooManyRequests {
		t.Fatal("another account shares the bucket")
	}
}

// Each step moves the row forward once; nothing replaces a key a step already fixed.
func TestLinkStepsRunInOrderOnce(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer := trusted.secondSession(t)
	id := createLinkRequest(t, newcomer, commitment)
	send := func(p *pairClient, suffix, field string, key []byte) int {
		code, _ := status(t, p.do(t, http.MethodPost, linkPath(id, suffix), []byte(`{`+quote(field)+`:`+quote(b64(key))+`}`), true, false))
		return code
	}
	if send(newcomer, "/reveal", "newcomerKey", newcomerKey) != http.StatusNotFound {
		t.Fatal("revealed before a claim")
	}
	if send(trusted, "/claim", "approverKey", approverKey) != http.StatusNoContent || send(newcomer, "/reveal", "newcomerKey", newcomerKey) != http.StatusNoContent {
		t.Fatal("claim and reveal")
	}
	other := bytes.Repeat([]byte{3}, 32)
	if send(newcomer, "/reveal", "newcomerKey", other) != http.StatusNotFound || send(trusted, "/claim", "approverKey", other) != http.StatusNotFound {
		t.Fatal("a fixed key was offered again")
	}
	var nk, ak []byte
	if err := trusted.db.QueryRow(`SELECT newcomer_key,approver_key FROM link_requests WHERE id=?`, id).Scan(&nk, &ak); err != nil || !bytes.Equal(nk, newcomerKey) || !bytes.Equal(ak, approverKey) {
		t.Fatal("stored keys moved", err)
	}
}

// Refusals are audited under the step's event with the response status, never with key material.
func TestLinkRefusalsAreAuditedWithoutSecrets(t *testing.T) {
	commitment, newcomerKey, approverKey := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	newcomer := trusted.secondSession(t)
	id := createLinkRequest(t, newcomer, commitment)
	other := trusted.addUser(t, "other")
	if code, _ := status(t, other.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusNotFound {
		t.Fatal("other claimed", code)
	}
	var actor, object string
	if err := trusted.db.QueryRow(`SELECT actor_user_id,object_id FROM audit_events WHERE event='identity.link.claim' AND outcome='denied' AND reason_code='404'`).Scan(&actor, &object); err != nil || actor != other.id || object != id {
		t.Fatal("claim refusal audit", actor, object, err)
	}
	if code, _ := status(t, newcomer.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":"short"}`), true, false)); code != http.StatusBadRequest || refused(t, trusted, "identity.link.request", "400") != 1 {
		t.Fatal("create refusal not audited", code)
	}
	if code, _ := status(t, newcomer.do(t, http.MethodPost, linkPath("not-an-id", "/reveal"), []byte(`{}`), true, false)); code != http.StatusNotFound {
		t.Fatal("malformed id", code)
	}
	var stray int
	if err := trusted.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE object_id='not-an-id'`).Scan(&stray); err != nil || stray != 0 || refused(t, trusted, "identity.link.reveal", "404") != 1 {
		t.Fatal("a caller-chosen path reached the audit", stray, err)
	}
	if code, _ := status(t, trusted.do(t, http.MethodPost, linkPath(id, "/claim"), []byte(`{"approverKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusNoContent {
		t.Fatal("claim", code)
	}
	if code, _ := status(t, newcomer.do(t, http.MethodPost, linkPath(id, "/reveal"), []byte(`{"newcomerKey":`+quote(b64(approverKey))+`}`), true, false)); code != http.StatusBadRequest {
		t.Fatal("mismatch", code)
	}
	if leak := auditLeaks(t, trusted, commitment, newcomerKey, approverKey); leak != "" {
		t.Fatal("audit carries key material:", leak)
	}
}

// Claim, reveal, approve and cancel share one per-account bucket, which also bounds refusal audit rows.
func TestLinkStepsAreRateLimitedPerAccount(t *testing.T) {
	trusted := newPairClient(t, strings.Repeat("p", 32))
	limit := config.Defaults().RateLimit.LoginPerMinute
	for i := 0; i < limit; i++ {
		if code, _ := status(t, trusted.do(t, http.MethodDelete, linkPath(mint(t, "lnk"), ""), nil, true, false)); code != http.StatusNotFound {
			t.Fatal(i, code)
		}
	}
	res := trusted.do(t, http.MethodDelete, linkPath(mint(t, "lnk"), ""), nil, true, false)
	if code, _ := status(t, res); code != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "6" { // refills 10 a minute
		t.Fatal("step past the account's bucket", code, res.Header.Get("Retry-After"))
	}
	if n := refused(t, trusted, "identity.link.cancel", "404"); n != limit {
		t.Fatal("refusal audits", n)
	}
	other := trusted.addUser(t, "other")
	if code, _ := status(t, other.do(t, http.MethodDelete, linkPath(mint(t, "lnk"), ""), nil, true, false)); code != http.StatusNotFound {
		t.Fatal("another account shares the bucket", code)
	}
}

// A password an administrator knows proves nothing about the user: it cannot start a link.
func TestAdminKnownPasswordCannotStartALink(t *testing.T) {
	commitment, _, _ := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	if _, err := trusted.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	newcomer := trusted.secondSession(t)
	code, body := status(t, newcomer.do(t, http.MethodPost, "/api/v1/me/link-requests", []byte(`{"commitment":`+quote(b64(commitment))+`}`), true, false))
	if code != http.StatusConflict || !strings.Contains(body, "password_change_required") || refused(t, trusted, "identity.link.request", "409") != 1 {
		t.Fatal("admin-known password started a link", code, body)
	}
}

// The approver list shows only the caller's own account.
func TestLinkCrossAccountList(t *testing.T) {
	commitment, _, _ := firstLinkVector(t)
	trusted := newPairClient(t, strings.Repeat("p", 32))
	trusted.createIdentity(t)
	id := createLinkRequest(t, trusted.secondSession(t), commitment)
	other := trusted.addUser(t, "other")
	if code, body := status(t, other.do(t, http.MethodGet, "/api/v1/me/link-requests", nil, false, false)); code != http.StatusOK || strings.Contains(body, id) {
		t.Fatal("another account listed the request", code, body)
	}
}
