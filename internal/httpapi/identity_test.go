package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestIdentityRowCannotAuthenticateAsDevice(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.deviceID = p.createIdentity(t)
	var stored string
	if err := p.db.QueryRow(`SELECT secret_hash FROM devices WHERE id=?`, p.deviceID).Scan(&stored); err != nil || !strings.HasPrefix(stored, "identity:") {
		t.Fatalf("secret_hash=%q %v", stored, err)
	}
	// Even a usable hash planted on the row must not authenticate it.
	p.deviceSecret = strings.Repeat("b", 48)
	sum := sha256.Sum256([]byte(p.deviceSecret))
	if _, err := p.db.Exec(`UPDATE devices SET secret_hash=? WHERE id=?`, "sha256:"+hex.EncodeToString(sum[:]), p.deviceID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/containers", "/api/v1/devices/" + p.deviceID + "/containers"} {
		if code, _ := status(t, p.doDeviceOnly(t, http.MethodGet, path, nil)); code != http.StatusUnauthorized {
			t.Fatalf("identity row authenticated on %s: %d", path, code)
		}
	}
}

func TestIdentityRowHiddenFromDeviceRoutes(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	_, body := status(t, p.do(t, http.MethodGet, "/api/v1/devices", nil, false, false))
	if strings.Contains(body, id) || strings.Contains(body, "identity") {
		t.Fatalf("identity listed: %s", body)
	}
	if code, _ := status(t, p.do(t, http.MethodDelete, "/api/v1/devices/"+id, nil, true, false)); code != http.StatusNotFound {
		t.Fatalf("identity revocable: %d", code)
	}
	if code, _ := status(t, p.do(t, http.MethodGet, "/api/v1/devices/"+id+"/containers", nil, false, false)); code != http.StatusNotFound {
		t.Fatalf("identity selection readable: %d", code)
	}
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/devices/"+id+"/containers", []byte(`{"containerIds":[]}`), true, false)); code != http.StatusNotFound {
		t.Fatalf("identity selection writable: %d", code)
	}
	var revoked string
	if err := p.db.QueryRow(`SELECT revoked_at FROM devices WHERE id=?`, id).Scan(&revoked); err != nil || revoked != "" {
		t.Fatalf("identity row changed: %q %v", revoked, err)
	}
}

func TestRegisterCannotClaimIdentity(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	id := p.createIdentity(t)
	body := []byte(`{"pairingToken":` + quote(p.mintToken(t)) + `,"publicKey":` + quote(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))) + `,"platform":"identity","labelCiphertext":""}`)
	if code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/devices/register", body, false, false)); code != http.StatusBadRequest {
		t.Fatalf("platform identity registered: %d", code)
	}
	if _, secret, code := p.register(t, p.mintToken(t), identityPub); code == http.StatusOK || secret != "" {
		t.Fatalf("identity key re-paired as a phone: %d", code)
	}
	var platform, hash string
	if err := p.db.QueryRow(`SELECT platform,secret_hash FROM devices WHERE id=?`, id).Scan(&platform, &hash); err != nil || platform != "identity" || !strings.HasPrefix(hash, "identity:") {
		t.Fatalf("identity row taken over: %q %q %v", platform, hash, err)
	}
}

func TestIdentityDoesNotBlockSaves(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.createIdentity(t)
	res := p.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false)
	var c struct {
		ID string `json:"id"`
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if json.Unmarshal(data, &c) != nil || c.ID == "" {
		t.Fatalf("container=%d %s", res.StatusCode, data)
	}
	var missing int
	if err := p.db.QueryRow(missingEnvelopesSQL, c.ID, c.ID, 1).Scan(&missing); err != nil || missing != 0 {
		t.Fatalf("identity row trips the save gate: %d %v", missing, err)
	}
}

func TestPasswordChangeRewrapsIdentityAtomically(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	change := func(wrapped string) (int, string) {
		body := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":100000`
		if wrapped != "" {
			body += `,"wrappedIdentityKey":` + quote(wrapped)
		}
		return status(t, p.do(t, http.MethodPost, "/api/v1/auth/password", []byte(body+`}`), true, false))
	}
	rewrapped := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, wrappedIdentityBytes))
	if code, _ := change(rewrapped); code != http.StatusConflict {
		t.Fatalf("rewrap without identity: %d", code)
	}
	p.createIdentity(t)
	if code, body := change(""); code != http.StatusConflict || !strings.Contains(body, "identity_rewrap_required") {
		t.Fatalf("old client orphaned the identity: %d %s", code, body)
	}
	if code, _ := change(base64.StdEncoding.EncodeToString(make([]byte, 59))); code != http.StatusBadRequest {
		t.Fatalf("short rewrap: %d", code)
	}
	var salt string
	if err := p.db.QueryRow(`SELECT login_salt FROM users WHERE id=?`, pairUser).Scan(&salt); err != nil || salt == "bmV3c2FsdA==" {
		t.Fatalf("refused change still committed the password: %q %v", salt, err)
	}
	if code, body := change(rewrapped); code != http.StatusNoContent {
		t.Fatalf("change: %d %s", code, body)
	}
	var wrapped []byte
	if err := p.db.QueryRow(`SELECT u.login_salt,i.wrapped_private_key FROM users u JOIN user_identities i ON i.user_id=u.id WHERE u.id=?`, pairUser).Scan(&salt, &wrapped); err != nil || salt != "bmV3c2FsdA==" || !bytes.Equal(wrapped, bytes.Repeat([]byte{5}, wrappedIdentityBytes)) {
		t.Fatalf("password and identity not committed together: %q %v", salt, err)
	}
}

func TestRecoveryAndAdminResetDeleteIdentity(t *testing.T) {
	for _, path := range []string{"recover", "admin"} {
		t.Run(path, func(t *testing.T) {
			p := newPairClient(t, strings.Repeat("p", 32))
			id := p.createIdentity(t)
			now := time.Now().UTC().Format(time.RFC3339)
			if _, err := p.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_00000000000000000000000000','workbook',?,?,?)`, pairUser, now, now); err != nil {
				t.Fatal(err)
			}
			if _, err := p.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('env_00000000000000000000000000','cnt_00000000000000000000000000',?,1,'x25519-hkdf-sha256-chacha20poly1305',x'01',?)`, id, now); err != nil {
				t.Fatal(err)
			}
			salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
			if path == "recover" {
				code, hash, err := auth.NewRecoveryCode()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.db.Exec(`UPDATE users SET recovery_hash=? WHERE id=?`, hash, pairUser); err != nil {
					t.Fatal(err)
				}
				body := `{"username":"pair","recoveryCode":` + quote(code) + `,"newAuthSecret":"` + strings.Repeat("d", 64) + `","newLoginSalt":"` + salt + `","iterations":100000}`
				if got, b := status(t, p.do(t, http.MethodPost, "/api/v1/auth/recover", []byte(body), false, false)); got != http.StatusOK {
					t.Fatalf("recover=%d %s", got, b)
				}
			} else {
				if _, err := p.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, pairUser); err != nil {
					t.Fatal(err)
				}
				p.stepUp(t)
				body := `{"newAuthSecret":"` + strings.Repeat("d", 64) + `","newLoginSalt":"` + salt + `","iterations":100000}`
				if got, b := status(t, p.do(t, http.MethodPost, "/api/v1/admin/users/"+pairUser+"/password", []byte(body), true, false)); got != http.StatusNoContent {
					t.Fatalf("admin reset=%d %s", got, b)
				}
			}
			var devices, identities, envelopes int
			if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM devices WHERE id=?),(SELECT COUNT(*) FROM user_identities),(SELECT COUNT(*) FROM key_envelopes)`, id).Scan(&devices, &identities, &envelopes); err != nil || devices+identities+envelopes != 0 {
				t.Fatalf("identity survived %s: devices=%d identities=%d envelopes=%d %v", path, devices, identities, envelopes, err)
			}
			var audited int
			if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.delete' AND object_id=? AND outcome='success'`, id).Scan(&audited); err != nil || audited != 1 {
				t.Fatalf("identity.delete audit=%d %v", audited, err)
			}
		})
	}
}
