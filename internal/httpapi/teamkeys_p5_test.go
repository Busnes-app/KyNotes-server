package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	p.setRecovery(t, id, "", recoveryCopy) // create and set: two of the 20 an hour (config.Defaults pairing_per_hour)
	for i := 0; i < 18; i++ {
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

// resetBody is a local (password) reset: per spec §8 the new identity gets a password copy, as a
// first one does (ruling D-P5-2 reversed), and the recovery copy in extra.
func resetBody(pub []byte, extra string) []byte {
	return []byte(`{"publicKey":` + quote(b64s(pub)) + `,"wrapAlg":"` + identityWrapAlg + `","wrappedPrivateKey":` + quote(b64s(identityWrapped)) + extra + `}`)
}

const resetRecovery = `,"replace":true,"recovery":{"wrapAlg":"` + recoveryWrapAlg + `","wrappedKey":"`

func expecting(deviceID string) string { return `,"expectedDeviceId":` + quote(deviceID) }

func TestIdentityResetReplacesTheIdentityAndEveryKeyItHeld(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	old := p.createIdentity(t)
	_, oldRecovery := p.setRecovery(t, old, "", recoveryCopy2)
	now := "2026-10-08T00:00:00Z"
	if _, err := p.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_00000000000000000000000000','workbook',?,?,?)`, pairUser, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('env_00000000000000000000000000','cnt_00000000000000000000000000',?,1,'x25519-hkdf-sha256-chacha20poly1305',x'01',?)`, old, now); err != nil {
		t.Fatal(err)
	}
	// A paired device credential (mintable with a session alone) and its envelope; with the clash
	// fixture below, two device credentials are revoked.
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{5}, 32))
	if _, err := p.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('env_phone0000000000000000000000','cnt_00000000000000000000000000',?,1,'x25519-hkdf-sha256-chacha20poly1305',x'01',?)`, p.deviceID, now); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, p.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusOK {
		t.Fatal("paired device before the reset", code)
	}
	commitment, _, _ := firstLinkVector(t)
	other := p.secondSession(t)
	createLinkRequest(t, other, commitment)
	newPub := bytes.Repeat([]byte{8}, 32)
	put := func(body []byte) (int, string) {
		return status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", body, true, false))
	}
	valid := resetBody(newPub, expecting(old)+resetRecovery+b64s(recoveryCopy)+`"}`)
	for name, body := range map[string][]byte{
		"replace without a copy":           resetBody(newPub, expecting(old)+`,"replace":true`),
		"replace without a password copy":  []byte(`{"publicKey":` + quote(b64s(newPub)) + `,"wrapAlg":"none"` + expecting(old) + resetRecovery + b64s(recoveryCopy) + `"}}`),
		"copy without replace":             resetBody(newPub, `,"recovery":{"wrapAlg":"`+recoveryWrapAlg+`","wrappedKey":"`+b64s(recoveryCopy)+`"}`),
		"expectedDeviceId without replace": resetBody(newPub, expecting(old)),
		"short copy":                       resetBody(newPub, expecting(old)+resetRecovery+b64s(recoveryCopy[:10])+`"}`),
		"replace without expectedDeviceId": resetBody(newPub, resetRecovery+b64s(recoveryCopy)+`"}`),
	} {
		p.stepUp(t)
		if code, out := put(body); code != http.StatusBadRequest {
			t.Fatal(name, code, out)
		}
	}
	if _, err := p.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
		t.Fatal(err)
	}
	if _, out := put(valid); !strings.Contains(out, "step_up_required") {
		t.Fatal("reset without a step-up", out)
	}
	p.stepUp(t)
	if _, err := p.db.Exec(`UPDATE users SET password_admin_known=1 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, out := put(valid); code != http.StatusConflict || !strings.Contains(out, "password_change_required") {
		t.Fatal("reset with an administrator-known password", code, out)
	}
	if _, err := p.db.Exec(`UPDATE users SET password_admin_known=0 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	// Compare-and-swap: a reset that names another identity (a stale tab) changes nothing.
	for _, stale := range []string{"", mint(t, "dev")} {
		if code, out := put(resetBody(newPub, expecting(stale)+resetRecovery+b64s(recoveryCopy)+`"}`)); code != http.StatusConflict || !strings.Contains(out, "already_exists") {
			t.Fatal("reset against a stale identity", stale, code, out)
		}
	}
	if rid, copy := storedRecovery(t, p); rid != oldRecovery || !bytes.Equal(copy, recoveryCopy2) {
		t.Fatal("a refused reset changed the recovery copy")
	}
	// One transaction: a create that fails after the delete (a fingerprint already registered) leaves
	// the old identity, its envelope and its recovery copy in place.
	clash := bytes.Repeat([]byte{3}, 32)
	clashFP := sha256.Sum256(clash)
	if _, err := p.db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,?,?,'sha256:x','android',?)`, mint(t, "dev"), pairUser, b64s(clash), hex.EncodeToString(clashFP[:]), now); err != nil {
		t.Fatal(err)
	}
	if code, out := put(resetBody(clash, expecting(old)+resetRecovery+b64s(recoveryCopy)+`"}`)); code != http.StatusConflict || !strings.Contains(out, "identity_exists") {
		t.Fatal("clashing reset", code, out)
	}
	// Resetting to the old identity's own key would leave a stolen browser holding it.
	if code, out := put(resetBody(identityPub, expecting(old)+resetRecovery+b64s(recoveryCopy)+`"}`)); code != http.StatusConflict || !strings.Contains(out, "identity_exists") {
		t.Fatal("reset to the old key", code, out)
	}
	var kept int
	if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM user_identities WHERE device_id=?)+(SELECT COUNT(*) FROM key_envelopes WHERE device_id=?)+(SELECT COUNT(*) FROM sessions WHERE revoked_at='')+(SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at='')`, old, old, p.deviceID).Scan(&kept); err != nil || kept != 5 {
		t.Fatal("a failed reset committed part of its work", kept, err)
	}
	code, out := put(valid)
	var created struct{ DeviceID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &created) != nil || created.DeviceID == old {
		t.Fatal("reset", code, out)
	}
	// The same request again names an identity that is gone: refused, the new one stays.
	if code, _ := put(valid); code != http.StatusConflict {
		t.Fatal("a repeated reset replaced the new identity", code)
	}
	if code, _ := status(t, p.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusUnauthorized {
		t.Fatal("a paired device credential survived the reset", code)
	}
	var oldRows, envelopes, links int
	if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM devices WHERE id=?),(SELECT COUNT(*) FROM key_envelopes),(SELECT COUNT(*) FROM link_requests)`, old).Scan(&oldRows, &envelopes, &links); err != nil || oldRows+envelopes+links != 0 {
		t.Fatalf("left behind: device=%d envelopes=%d links=%d %v", oldRows, envelopes, links, err)
	}
	// The password user keeps the password unlock path (spec §8) and gets the new recovery copy.
	var alg string
	var wrapped []byte
	if err := p.db.QueryRow(`SELECT wrap_alg,wrapped_private_key FROM user_identities WHERE device_id=?`, created.DeviceID).Scan(&alg, &wrapped); err != nil || alg != identityWrapAlg || !bytes.Equal(wrapped, identityWrapped) {
		t.Fatal("new identity without its password copy", alg, len(wrapped), err)
	}
	if rid, copy := storedRecovery(t, p); rid == "" || rid == oldRecovery || !bytes.Equal(copy, recoveryCopy) {
		t.Fatal("new identity without its recovery copy")
	}
	// Every other session of the account ends; the one that reset keeps working.
	if code, _ := status(t, other.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)); code != http.StatusUnauthorized {
		t.Fatal("another session survived the reset", code)
	}
	if code, _ := status(t, p.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)); code != http.StatusOK {
		t.Fatal("the resetting session ended", code)
	}
	var reset, createdAudit int
	if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_events WHERE event='identity.reset' AND object_id=? AND reason_code='sessions_revoked=1,devices_revoked=2'),(SELECT COUNT(*) FROM audit_events WHERE event='identity.create' AND object_id=? AND reason_code='wrap=aes-256-gcm,proof=password,reset')`, old, created.DeviceID).Scan(&reset, &createdAudit); err != nil || reset != 1 || createdAudit != 1 {
		t.Fatal("audits", reset, createdAudit, err)
	}
}

// Device-only identities stay device-only through a reset: an SSO session can never send a password copy.
func TestSSOResetStaysDeviceOnly(t *testing.T) {
	f := newLogoutFixture(t)
	cookies, bob := ssoPerson(f, "bob", "bob-1")
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", deviceOnlyBody(identityPub)); r.Code != 200 {
		t.Fatal("device-only create", r.Code, r.Body.String())
	}
	var old string
	if err := f.db.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, bob).Scan(&old); err != nil {
		t.Fatal(err)
	}
	newPub := bytes.Repeat([]byte{8}, 32)
	withPassword := string(resetBody(newPub, expecting(old)+resetRecovery+b64s(recoveryCopy)+`"}`))
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", withPassword); r.Code != 400 {
		t.Fatal("SSO reset with a password copy", r.Code, r.Body.String())
	}
	deviceOnly := `{"publicKey":` + quote(b64s(newPub)) + `,"wrapAlg":"none"` + expecting(old) + resetRecovery + b64s(recoveryCopy) + `"}}`
	if r := ssoDo(f, cookies, "bob", "PUT", "/api/v1/me/identity", deviceOnly); r.Code != 200 {
		t.Fatal("SSO reset", r.Code, r.Body.String())
	}
	var alg, rid string
	var wrapped []byte
	if err := f.db.QueryRow(`SELECT wrap_alg,wrapped_private_key,recovery_id FROM user_identities WHERE user_id=?`, bob).Scan(&alg, &wrapped, &rid); err != nil || alg != deviceOnlyWrapAlg || len(wrapped) != 0 || rid == "" {
		t.Fatal("after SSO reset", alg, len(wrapped), rid, err)
	}
}

// With no identity before, the create row carries what the reset revoked.
func TestIdentityResetWithoutAnIdentityAuditsRevocations(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.secondSession(t)
	p.stepUp(t)
	code, out := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", resetBody(identityPub, expecting("")+resetRecovery+b64s(recoveryCopy)+`"}`), true, false))
	var created struct{ DeviceID string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &created) != nil {
		t.Fatal("reset with no identity", code, out)
	}
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.create' AND object_id=? AND reason_code='wrap=aes-256-gcm,proof=password,reset,sessions_revoked=1,devices_revoked=0'`, created.DeviceID).Scan(&n); err != nil || n != 1 {
		t.Fatal("create audit without the revoked counts", n, err)
	}
}

// A compare-and-swap UPDATE that touches no row is a conflict, never a success with an unstored ID.
func TestIdentityRecoverySetChecksRowsAffected(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	if _, err := p.db.Exec(`CREATE TRIGGER skip_recovery BEFORE UPDATE OF recovery_id ON user_identities BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if code, _ := p.setRecovery(t, id, "", recoveryCopy); code != http.StatusConflict {
		t.Fatal("an unapplied set answered", code)
	}
	var audited int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.recovery.set'`).Scan(&audited); err != nil || audited != 0 {
		t.Fatal("an unapplied set was audited", audited, err)
	}
}

// Identity create and reset share the per-account recovery bucket.
func TestIdentityResetIsRateLimitedPerAccount(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	for i := 0; i < 20; i++ {
		if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", []byte(`{}`), true, false)); code == http.StatusTooManyRequests {
			t.Fatal("limited early", i)
		}
	}
	res := p.do(t, http.MethodPut, "/api/v1/me/identity", []byte(`{}`), true, false)
	if code, _ := status(t, res); code != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "180" {
		t.Fatal("21st identity write in an hour", code)
	}
}

// A save whose response was lost is re-sent with the old expectation. The byte-identical copy is that
// request's own upload (every seal has a fresh salt and nonce), so it answers 200 with the live ID and
// changes nothing; other bytes are still a lost race.
func TestIdentityRecoveryReplayOfTheStoredCopyIsIdempotent(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	code, first := p.setRecovery(t, id, "", recoveryCopy)
	if code != http.StatusOK {
		t.Fatal("first set", code)
	}
	var at string
	if err := p.db.QueryRow(`SELECT recovery_updated_at FROM user_identities WHERE user_id=?`, pairUser).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if code, again := p.setRecovery(t, id, "", recoveryCopy); code != http.StatusOK || again != first {
		t.Fatalf("replay=%d %q, want 200 %q", code, again, first)
	}
	if code, _ := p.setRecovery(t, mint(t, "dev"), "", recoveryCopy); code != http.StatusConflict {
		t.Fatal("replay for another identity", code)
	}
	if code, _ := p.setRecovery(t, id, "", recoveryCopy2); code != http.StatusConflict {
		t.Fatal("other bytes", code)
	}
	var now string
	if err := p.db.QueryRow(`SELECT recovery_updated_at FROM user_identities WHERE user_id=?`, pairUser).Scan(&now); err != nil {
		t.Fatal(err)
	}
	if got, wrapped := storedRecovery(t, p); got != first || !bytes.Equal(wrapped, recoveryCopy) || now != at {
		t.Fatal("a replay rewrote the copy")
	}
	var replayed int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.recovery.set' AND reason_code='replayed' AND object_id=?`, id).Scan(&replayed); err != nil || replayed != 1 {
		t.Fatalf("replay audit=%d %v", replayed, err)
	}
}

// A KySignOn-linked account never gets a password copy back, even through a local session's reset:
// the reset must be device-only. A password account's reset keeps its password copy (spec §8).
func TestLinkedAccountResetIsDeviceOnlyFromALocalSession(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	old := p.createIdentity(t)
	if _, err := p.db.Exec(`UPDATE users SET sso_issuer='https://sso.example',sso_subject='pair-sub' WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	newPub := bytes.Repeat([]byte{8}, 32)
	p.stepUp(t)
	if code, out := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", resetBody(newPub, expecting(old)+resetRecovery+b64s(recoveryCopy)+`"}`), true, false)); code != http.StatusConflict || errorCode(t, out) != "device_only_required" {
		t.Fatal("linked account reset with a password copy", code, out)
	}
	var kept string
	if err := p.db.QueryRow(`SELECT device_id FROM user_identities WHERE user_id=?`, pairUser).Scan(&kept); err != nil || kept != old {
		t.Fatal("a refused reset changed the identity", kept, err)
	}
	deviceOnly := []byte(`{"publicKey":` + quote(b64s(newPub)) + `,"wrapAlg":"none"` + expecting(old) + resetRecovery + b64s(recoveryCopy) + `"}}`)
	if code, out := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", deviceOnly, true, false)); code != http.StatusOK {
		t.Fatal("linked account device-only reset", code, out)
	}
	var alg string
	var wrapped []byte
	if err := p.db.QueryRow(`SELECT wrap_alg,wrapped_private_key FROM user_identities WHERE user_id=?`, pairUser).Scan(&alg, &wrapped); err != nil || alg != deviceOnlyWrapAlg || len(wrapped) != 0 {
		t.Fatal("after the reset", alg, len(wrapped), err)
	}
	// Nor does the stripped copy come back through a password change (passwordCopyAddableSQL).
	if identity, err := loadIdentity(p.db, pairUser, false); err != nil || identity["passwordCopy"] != "" {
		t.Fatal("a linked account's copy is addable", identity, err)
	}
}

// Only stewards (owner, admin) manage members or create team notebooks.
func TestNonStewardsCannotManageMembersOrCreateTeamNotebooks(t *testing.T) {
	tm := newTeam(t)
	for name, m := range map[string]member{"editor": tm.editor, "viewer": tm.viewer} {
		other := tm.admin.id
		requests := map[string]struct {
			method, path string
			body         []byte
		}{
			"remove":        {http.MethodDelete, "/api/v1/containers/" + tm.id + "/members/" + other, nil},
			"invite":        {http.MethodPost, "/api/v1/containers/" + tm.id + "/invitations", []byte(`{"inviteeId":` + quote(mint(t, "usr")) + `,"role":"viewer"}`)},
			"team notebook": {http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","teamId":` + quote(tm.id) + `}`)},
		}
		for route, req := range requests {
			if code, out := status(t, m.do(t, req.method, req.path, req.body, true, false)); code != http.StatusForbidden {
				t.Fatal(name, route, code, out)
			}
		}
	}
	var members, invitations, notebooks int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM memberships WHERE container_id=? AND revoked_at=''),(SELECT COUNT(*) FROM invitations),(SELECT COUNT(*) FROM containers WHERE team_id=?)`, tm.id, tm.id).Scan(&members, &invitations, &notebooks); err != nil || members != 4 || invitations != 0 || notebooks != 1 {
		t.Fatal("a refused request changed something", members, invitations, notebooks, err)
	}
}

// The creator undoes a failed creation at any time, a team admin included: the server checks in the
// transaction that the notebook was never keyed and holds nothing. Anything else keeps the owner-only,
// recent-sign-in rule.
func TestCreatorDeletesABlankNotebookWithoutARecentSignIn(t *testing.T) {
	tm := newTeam(t)
	create := func(m *pairClient) string {
		t.Helper()
		code, out := status(t, m.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","teamId":`+quote(tm.id)+`}`), true, false))
		var c struct{ ID string }
		if code != http.StatusOK || json.Unmarshal([]byte(out), &c) != nil {
			t.Fatal("create", code, out)
		}
		return c.ID
	}
	del := func(m *pairClient, cid string) int {
		t.Helper()
		code, _ := status(t, m.do(t, http.MethodDelete, "/api/v1/containers/"+cid, nil, true, false))
		return code
	}
	blank, withNote, keyed, ownerBlank := create(tm.admin.pairClient), create(tm.admin.pairClient), create(tm.admin.pairClient), create(tm.owner)
	enveloped, invited, demoted := create(tm.admin.pairClient), create(tm.admin.pairClient), create(tm.admin.pairClient)
	if _, code := tm.admin.save(t, withNote, "", 1); code == 0 {
		t.Fatal("object")
	}
	if _, err := tm.owner.db.Exec(`UPDATE containers SET shared_generation=1 WHERE id=?`, keyed); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,1,'x25519-hkdf-sha256-chacha20poly1305',x'01','now')`, mint(t, "env"), enveloped, tm.adminID); err != nil {
		t.Fatal(err)
	}
	outsider := tm.owner.addUser(t, "outsider")
	if code, out := status(t, tm.admin.do(t, http.MethodPost, "/api/v1/containers/"+invited+"/invitations", []byte(`{"inviteeId":`+quote(outsider.id)+`,"role":"viewer"}`), true, false)); code != http.StatusOK {
		t.Fatal("invite", code, out)
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='editor' WHERE container_id=? AND user_id=?`, demoted, tm.admin.id); err != nil {
		t.Fatal(err)
	}
	// Teams the owner created: one alone, one with another member.
	newTeamOf := func(withMember bool) string {
		code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"team"}`), true, false))
		var c struct{ ID string }
		if code != http.StatusOK || json.Unmarshal([]byte(out), &c) != nil {
			t.Fatal("create team", code, out)
		}
		if withMember {
			if _, err := tm.owner.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'viewer','now')`, mint(t, "mem"), c.ID, tm.viewer.id); err != nil {
				t.Fatal(err)
			}
		}
		return c.ID
	}
	loneTeam, sharedTeam := newTeamOf(false), newTeamOf(true)
	// Every session is older than the five-minute window.
	if _, err := tm.owner.db.Exec(`UPDATE sessions SET created_at='2020-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if code := del(tm.editor.pairClient, ownerBlank); code != http.StatusForbidden {
		t.Fatal("a member who did not create it", code)
	}
	if code := del(tm.owner, blank); code != http.StatusForbidden {
		t.Fatal("a steward who did not create it, outside the window", code)
	}
	if code := del(tm.admin.pairClient, withNote); code != http.StatusForbidden {
		t.Fatal("not empty", code)
	}
	for name, cid := range map[string]string{"keyed": keyed, "an envelope": enveloped, "an invitation": invited, "a creator no longer a steward": demoted} {
		if code := del(tm.admin.pairClient, cid); code != http.StatusForbidden {
			t.Fatal(name, code)
		}
	}
	if code := del(tm.owner, sharedTeam); code != http.StatusForbidden {
		t.Fatal("a team with another member", code)
	}
	if code := del(tm.owner, loneTeam); code != http.StatusNoContent {
		t.Fatal("a team with no other member", code)
	}
	if code := del(tm.owner, tm.id); code != http.StatusForbidden {
		t.Fatal("the owner outside the window, a team that holds notebooks", code)
	}
	if code := del(tm.admin.pairClient, blank); code != http.StatusNoContent {
		t.Fatal("the creator's blank notebook", code)
	}
	if code := del(tm.owner, ownerBlank); code != http.StatusNoContent {
		t.Fatal("the owner's blank notebook", code)
	}
	var live int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM containers WHERE id IN (?,?) AND deleted_at=''`, blank, ownerBlank).Scan(&live); err != nil || live != 0 {
		t.Fatal("not deleted", live, err)
	}
	if code := del(tm.admin.pairClient, blank); code != http.StatusNotFound {
		t.Fatal("deleted twice", code)
	}
	var audited int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.delete' AND reason_code='blank' AND container_id IN (?,?,?)`, blank, ownerBlank, loneTeam).Scan(&audited); err != nil || audited != 3 {
		t.Fatal("blank deletes audited", audited, err)
	}
	var refusedChanged int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM containers WHERE id IN (?,?,?,?,?,?,?) AND deleted_at<>''`, withNote, keyed, enveloped, invited, demoted, sharedTeam, tm.id).Scan(&refusedChanged); err != nil || refusedChanged != 0 {
		t.Fatal("a refused delete deleted", refusedChanged, err)
	}
}

// An administrator's password reset ends paired device credentials in the same transaction, as the
// user's own reset and a password change do; the identity device stays.
func TestAdminPasswordResetRevokesPairedDevices(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	if _, err := p.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	victim := p.addUser(t, "victim")
	identity := victim.createIdentity(t)
	victim.deviceID, victim.deviceSecret, _ = victim.register(t, victim.mintToken(t), bytes.Repeat([]byte{5}, 32))
	cid := seedContainer(t, p, "workbook", "", map[string]string{victim.id: "owner"})
	for i, device := range []string{identity, victim.deviceID} {
		if _, err := p.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,1,'x25519-hkdf-sha256-chacha20poly1305',x'01','now')`, mint(t, "env"), cid, device); err != nil {
			t.Fatal(i, err)
		}
	}
	if code, _ := status(t, victim.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusOK {
		t.Fatal("paired device before the reset", code)
	}
	p.stepUp(t)
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	body := `{"newAuthSecret":"` + strings.Repeat("d", 64) + `","newLoginSalt":"` + salt + `","iterations":100000}`
	if code, out := status(t, p.do(t, http.MethodPost, "/api/v1/admin/users/"+victim.id+"/password", []byte(body), true, false)); code != http.StatusNoContent {
		t.Fatal("admin reset", code, out)
	}
	if code, _ := status(t, victim.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil)); code != http.StatusUnauthorized {
		t.Fatal("a paired device credential survived the admin reset", code)
	}
	var phone, kept int
	var revoked string
	if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM key_envelopes WHERE device_id=?),(SELECT COUNT(*) FROM key_envelopes WHERE device_id=?),(SELECT revoked_at FROM devices WHERE id=?)`, victim.deviceID, identity, identity).Scan(&phone, &kept, &revoked); err != nil || phone != 0 || kept != 1 || revoked != "" {
		t.Fatal("after the reset", phone, kept, revoked, err)
	}
}
