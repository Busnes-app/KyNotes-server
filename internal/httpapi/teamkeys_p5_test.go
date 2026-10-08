package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var (
	recoveryCopy  = bytes.Repeat([]byte{7}, recoveryWrapBytes)
	recoveryCopy2 = bytes.Repeat([]byte{6}, recoveryWrapBytes)
)

func b64s(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func recoveryBody(deviceID, expected string, wrapped []byte) []byte {
	return []byte(`{"deviceId":` + quote(deviceID) + `,"expectedRecoveryId":` + quote(expected) + `,"wrapAlg":"` + recoveryWrapAlg + `","wrappedKey":` + quote(b64s(wrapped)) + `}`)
}

// setRecovery returns the status and, on 200, the new recovery ID.
func (p *pairClient) setRecovery(t *testing.T, deviceID, expected string, wrapped []byte) (int, string) {
	t.Helper()
	code, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity/recovery", recoveryBody(deviceID, expected, wrapped), true, false))
	var out struct {
		RecoveryID string `json:"recoveryId"`
	}
	if code == http.StatusOK && (json.Unmarshal([]byte(body), &out) != nil || out.RecoveryID == "") {
		t.Fatalf("set recovery: %s", body)
	}
	return code, out.RecoveryID
}

func (p *pairClient) fetchRecovery(t *testing.T) (*http.Response, int, string) {
	t.Helper()
	res := p.do(t, http.MethodPost, "/api/v1/me/identity/recovery/fetch", nil, true, false)
	code, body := status(t, res)
	return res, code, body
}

func storedRecovery(t *testing.T, p *pairClient) (string, []byte) {
	t.Helper()
	var id string
	var wrapped []byte
	if err := p.db.QueryRow(`SELECT recovery_id,recovery_wrapped_key FROM user_identities WHERE user_id=?`, pairUser).Scan(&id, &wrapped); err != nil {
		t.Fatal(err)
	}
	return id, wrapped
}

// errorCode is the error code of a JSON error body; the request ID differs per call.
func errorCode(t *testing.T, body string) string {
	t.Helper()
	var out ErrorBody
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(body, err)
	}
	return out.Error.Code
}

func TestIdentityRecoveryNeedsStepUpCSRFAndAnIdentity(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.stepUp(t)
	if code, _ := p.setRecovery(t, mint(t, "dev"), "", recoveryCopy); code != http.StatusNotFound {
		t.Fatal("set without an identity", code)
	}
	_, noIdentity, noIdentityBody := p.fetchRecovery(t)
	id := p.createIdentity(t)
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity/recovery", recoveryBody(id, "", recoveryCopy), false, false)); code != http.StatusForbidden {
		t.Fatal("set without CSRF", code)
	}
	if code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/me/identity/recovery/fetch", nil, false, false)); code != http.StatusForbidden {
		t.Fatal("fetch without CSRF", code)
	}
	if _, err := p.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
		t.Fatal(err)
	}
	if _, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity/recovery", recoveryBody(id, "", recoveryCopy), true, false)); !strings.Contains(body, "step_up_required") {
		t.Fatal("set without a step-up", body)
	}
	if _, _, body := p.fetchRecovery(t); !strings.Contains(body, "step_up_required") {
		t.Fatal("fetch without a step-up", body)
	}
	p.stepUp(t)
	for name, body := range map[string][]byte{
		"alg":    bytes.Replace(recoveryBody(id, "", recoveryCopy), []byte(recoveryWrapAlg), []byte("aes-256-gcm"), 1),
		"short":  recoveryBody(id, "", recoveryCopy[:recoveryWrapBytes-1]),
		"device": recoveryBody("dev_bad", "", recoveryCopy),
	} {
		if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity/recovery", body, true, false)); code != http.StatusBadRequest {
			t.Fatal(name, code)
		}
	}
	// No identity and no copy answer alike, and both misses are audited without naming a copy.
	_, noCopy, noCopyBody := p.fetchRecovery(t)
	if noIdentity != http.StatusNotFound || noCopy != noIdentity || errorCode(t, noCopyBody) != errorCode(t, noIdentityBody) {
		t.Fatal("fetch misses differ", noIdentity, noIdentityBody, noCopy, noCopyBody)
	}
	var misses int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.recovery.fetch' AND outcome='denied' AND reason_code='none'`).Scan(&misses); err != nil || misses != 2 {
		t.Fatal("fetch misses audited", misses, err)
	}
}

func TestIdentityRecoveryIsCompareAndSwap(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	code, first := p.setRecovery(t, id, "", recoveryCopy)
	if code != http.StatusOK {
		t.Fatal("first set", code)
	}
	// A browser that never saw the first copy cannot replace it.
	if code, _ := p.setRecovery(t, id, "", recoveryCopy2); code != http.StatusConflict {
		t.Fatal("stale empty expectation", code)
	}
	if got, wrapped := storedRecovery(t, p); got != first || !bytes.Equal(wrapped, recoveryCopy) {
		t.Fatal("a refused set changed the copy")
	}
	if code, _ := p.setRecovery(t, mint(t, "dev"), first, recoveryCopy2); code != http.StatusConflict {
		t.Fatal("another identity's row", code)
	}
	code, second := p.setRecovery(t, id, first, recoveryCopy2)
	if code != http.StatusOK || second == first {
		t.Fatal("rotate", code, second)
	}
	// The old copy is gone: only the new code opens anything.
	if got, wrapped := storedRecovery(t, p); got != second || !bytes.Equal(wrapped, recoveryCopy2) {
		t.Fatal("rotation did not replace the copy")
	}
	for reason, want := range map[string]int{"created": 1, "replaced": 1} {
		var n int
		if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.recovery.set' AND reason_code=? AND object_id=?`, reason, id).Scan(&n); err != nil || n != want {
			t.Fatalf("audit %s=%d %v", reason, n, err)
		}
	}
	// Audit rows never carry the copy.
	var leaked int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE instr(reason_code,?)>0 OR instr(reason_code,?)>0`, b64s(recoveryCopy), b64s(recoveryCopy2)).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("an audit row carries the copy", leaked, err)
	}
}

func TestIdentityRecoveryCopyIsOnlyInTheFetch(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	_, rid := p.setRecovery(t, id, "", recoveryCopy)
	res, code, body := p.fetchRecovery(t)
	var got struct{ DeviceID, PublicKey, RecoveryID, WrapAlg, WrappedKey string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("fetch", code, body, res.Header.Get("Cache-Control"))
	}
	if got.DeviceID != id || got.PublicKey != b64s(identityPub) || got.RecoveryID != rid || got.WrapAlg != recoveryWrapAlg || got.WrappedKey != b64s(recoveryCopy) {
		t.Fatalf("fetched %+v", got)
	}
	var audited int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.recovery.fetch' AND outcome='success' AND object_id=? AND reason_code=?`, id, "recovery="+rid).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("fetch audit", audited, err)
	}
	// Never in a body a cookie or a password proof yields; GET names the copy, never carries it.
	_, me := status(t, p.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false))
	stepped := p.stepUp(t)
	_, login := status(t, p.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false))
	for name, out := range map[string]string{"GET": me, "step-up": stepped, "login": login} {
		if strings.Contains(out, b64s(recoveryCopy)) {
			t.Fatal(name, "carries the copy")
		}
	}
	if !strings.Contains(me, `"recoveryId":"`+rid+`"`) {
		t.Fatal("GET does not name the copy", me)
	}
}

func TestIdentityRecoveryRefusedWhileAnAdministratorKnowsThePassword(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	_, rid := p.setRecovery(t, id, "", recoveryCopy)
	if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	p.stepUp(t)
	if _, code, body := p.fetchRecovery(t); code != http.StatusConflict || !strings.Contains(body, "password_change_required") {
		t.Fatal("fetch", code, body)
	}
	if code, _ := p.setRecovery(t, id, rid, recoveryCopy2); code != http.StatusConflict {
		t.Fatal("set", code)
	}
	if got, _ := storedRecovery(t, p); got != rid {
		t.Fatal("refused set changed the copy")
	}
}

func TestIdentityRecoveryIsRateLimitedPerAccount(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	p.setRecovery(t, id, "", recoveryCopy) // one of the 20 an hour (config.Defaults pairing_per_hour)
	for i := 0; i < 19; i++ {
		if _, code, _ := p.fetchRecovery(t); code != http.StatusOK {
			t.Fatal("fetch", i, code)
		}
	}
	res, code, _ := p.fetchRecovery(t)
	if code != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "180" {
		t.Fatal("21st recovery request in an hour", code, res.Header.Get("Retry-After"))
	}
	other := p.addUser(t, "other")
	if code, _ := status(t, other.do(t, http.MethodPost, "/api/v1/me/identity/recovery/fetch", nil, true, false)); code == http.StatusTooManyRequests {
		t.Fatal("another account shares the bucket")
	}
}

// Without a session the bucket is keyed by the client IP, so unauthenticated probes are bounded too.
func TestIdentityRecoveryIsRateLimitedPerIPWithoutASession(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	anonymous := func() int {
		req, err := http.NewRequest(http.MethodPost, p.url+"/api/v1/me/identity/recovery/fetch", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	for i := 0; i < 20; i++ {
		if code := anonymous(); code != http.StatusUnauthorized {
			t.Fatal("anonymous fetch", i, code)
		}
	}
	if code := anonymous(); code != http.StatusTooManyRequests {
		t.Fatal("21st anonymous recovery request from one IP", code)
	}
}

// A fresh browser of an SSO account holds no identity and no password: the KySignOn confirmation
// for this exact request is its step-up, which is how it restores from the recovery code.
func TestSSOAccountSetsAndFetchesItsRecoveryCopyWithKySignOn(t *testing.T) {
	f := newLogoutFixture(t)
	cookies, bob := ssoPerson(f, "bob", "bob-1")
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", deviceOnlyBody(identityPub)); r.Code != 200 {
		t.Fatal("device-only create", r.Code, r.Body.String())
	}
	var dev string
	if err := f.db.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, bob).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	plain := withCookies(httptest.NewRequest("POST", "/api/v1/me/identity/recovery/fetch", nil), cookies)
	if r := f.send(plain); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("fetched without a KySignOn confirmation", r.Code, r.Body.String())
	}
	unconfirmed := withCookies(httptest.NewRequest("PUT", "/api/v1/me/identity/recovery", bytes.NewReader(recoveryBody(dev, "", recoveryCopy))), cookies)
	if r := f.send(unconfirmed); r.Code != 403 || !strings.Contains(r.Body.String(), "sso_step_up_required") {
		t.Fatal("set without a KySignOn confirmation", r.Code, r.Body.String())
	}
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity/recovery", string(recoveryBody(dev, "", recoveryCopy))); r.Code != 200 {
		t.Fatal("set", r.Code, r.Body.String())
	}
	fresh, _ := ssoPerson(f, "bob", "bob-2")
	if r := ssoDo(f, fresh, "bob", "POST", "/api/v1/me/identity/recovery/fetch", ""); r.Code != 200 || !strings.Contains(r.Body.String(), b64s(recoveryCopy)) {
		t.Fatal("fetch from a fresh browser", r.Code, r.Body.String())
	}
}
