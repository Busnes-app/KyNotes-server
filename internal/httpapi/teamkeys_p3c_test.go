package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if r := reauthAction(f, cookies, "", "/user-action", `{"x":2}`); r.Code != 409 || !strings.Contains(r.Body.String(), "step_up_pending") {
		t.Fatal("background challenge during a confirmation", r.Code, r.Body.String())
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
