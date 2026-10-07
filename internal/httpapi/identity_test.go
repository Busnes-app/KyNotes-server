package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

const pairUser = "usr_pair_test"

var (
	identityPub     = bytes.Repeat([]byte{9}, 32)
	identityWrapped = bytes.Repeat([]byte{4}, wrappedIdentityBytes)
)

func identityBody(pub, wrapped []byte) []byte {
	return []byte(`{"publicKey":` + quote(base64.StdEncoding.EncodeToString(pub)) + `,"wrapAlg":"aes-256-gcm","wrappedPrivateKey":` + quote(base64.StdEncoding.EncodeToString(wrapped)) + `}`)
}

func status(t *testing.T, res *http.Response) (int, string) {
	t.Helper()
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res.StatusCode, string(body)
}

func (p *pairClient) stepUp(t *testing.T) {
	t.Helper()
	if code, body := status(t, p.do(t, http.MethodPost, "/api/v1/auth/step-up", []byte(`{"authSecret":"`+strings.Repeat("a", 64)+`"}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("step-up=%d %s", code, body)
	}
}

// createIdentity returns the identity device ID.
func (p *pairClient) createIdentity(t *testing.T) string {
	t.Helper()
	p.stepUp(t)
	res := p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(identityPub, identityWrapped), true, false)
	var out struct {
		DeviceID string `json:"deviceId"`
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || json.Unmarshal(data, &out) != nil || out.DeviceID == "" {
		t.Fatalf("create identity=%d %s", res.StatusCode, data)
	}
	return out.DeviceID
}

func TestIdentityCreateRequiresStepUpCSRFAndIsCreateOnly(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(identityPub, identityWrapped), true, false)); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("without step-up: %d %s", code, body)
	}
	p.stepUp(t)
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(identityPub, identityWrapped), false, false)); code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", code)
	}
	for _, bad := range [][]byte{
		identityBody(identityPub[:31], identityWrapped),
		identityBody(identityPub, identityWrapped[:59]),
		bytes.Replace(identityBody(identityPub, identityWrapped), []byte("aes-256-gcm"), []byte("aes-128-gcm"), 1),
	} {
		if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", bad, true, false)); code != http.StatusBadRequest {
			t.Fatalf("malformed identity accepted: %d", code)
		}
	}
	first := p.createIdentity(t)
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(bytes.Repeat([]byte{8}, 32), identityWrapped), true, false)); code != http.StatusConflict || !strings.Contains(body, "identity_exists") {
		t.Fatalf("second create: %d %s", code, body)
	}
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND platform='identity'`, pairUser).Scan(&n); err != nil || n != 1 {
		t.Fatalf("identity rows=%d %v", n, err)
	}
	var audited int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.create' AND object_id=?`, first).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("identity.create audit=%d %v", audited, err)
	}
	stale := time.Now().UTC().Add(-auth.StepUpWindow - time.Minute).Format(time.RFC3339)
	if _, err := p.db.Exec(`UPDATE sessions SET stepup_at=? WHERE user_id=?`, stale, pairUser); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`DELETE FROM devices WHERE platform='identity'`); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(identityPub, identityWrapped), true, false)); code != http.StatusForbidden {
		t.Fatalf("stale step-up honoured: %d", code)
	}
}

func TestUserStepUpRefusesSSOSession(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.stepUp(t)
	if _, err := p.db.Exec(`UPDATE sessions SET sso_issuer='https://idp.example' WHERE user_id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(identityPub, identityWrapped), true, false)); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("SSO session created an identity: %d %s", code, body)
	}
}

func TestIdentityGetReturnsWrappedKeyToSessionOnly(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	if code, _ := status(t, p.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)); code != http.StatusNotFound {
		t.Fatalf("before create: %d", code)
	}
	id := p.createIdentity(t)
	res := p.do(t, http.MethodGet, "/api/v1/me/identity", nil, false, false)
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("identity response is cacheable")
	}
	var got map[string]string
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if json.Unmarshal(data, &got) != nil || got["deviceId"] != id || got["wrapAlg"] != "aes-256-gcm" ||
		got["publicKey"] != base64.StdEncoding.EncodeToString(identityPub) ||
		got["wrappedPrivateKey"] != base64.StdEncoding.EncodeToString(identityWrapped) || len(got["fingerprint"]) != 64 {
		t.Fatalf("identity=%s", data)
	}
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{7}, 32))
	if code, _ := status(t, p.doDeviceOnly(t, http.MethodGet, "/api/v1/me/identity", nil)); code != http.StatusUnauthorized {
		t.Fatalf("device credential read the wrapped identity: %d", code)
	}
}

func TestIdentityCreateRefusesPairedDeviceKey(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	phone := bytes.Repeat([]byte{7}, 32)
	if _, _, code := p.register(t, p.mintToken(t), phone); code != http.StatusOK {
		t.Fatalf("register=%d", code)
	}
	p.stepUp(t)
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/me/identity", identityBody(phone, identityWrapped), true, false)); code != http.StatusConflict || !strings.Contains(body, "identity_exists") {
		t.Fatalf("identity took a paired device key: %d %s", code, body)
	}
}
