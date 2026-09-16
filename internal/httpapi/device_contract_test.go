package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type pairClient struct {
	hc                                           *http.Client
	url, csrf, container, deviceID, deviceSecret string
}

func newPairClient(t *testing.T, pairing string) *pairClient {
	t.Helper()
	root := t.TempDir()
	s, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := blobstore.New(root)
	secret := strings.Repeat("a", 64)
	hash, _ := auth.HashAuthSecret(secret)
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, "usr_pair_test", "pair", hash, salt, 100000, "now", "now")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Server.Bind = "127.0.0.1:0"
	cfg.Secrets.PairingSecret = pairing
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), b, cfg))
	jar, _ := cookiejar.New(nil)
	p := &pairClient{hc: &http.Client{Jar: jar}, url: srv.URL}
	t.Cleanup(func() { srv.Close(); s.Close() })
	res := p.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+secret+`"}`), false, false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login=%d", res.StatusCode)
	}
	res.Body.Close()
	return p
}

func (p *pairClient) do(t *testing.T, method, path string, body []byte, csrf, device bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, p.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range p.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if csrf && c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	if device {
		req.Header.Set("X-Kynotes-Device-Id", p.deviceID)
		req.Header.Set("X-Kynotes-Device-Secret", p.deviceSecret)
	}
	res, err := p.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if c := res.Header.Get("Set-Cookie"); c != "" {
		_ = c
	}
	for _, c := range res.Cookies() {
		if c.Name == "csrf_token" {
			p.csrf = c.Value
		}
	}
	return res
}

func (p *pairClient) doDeviceOnly(t *testing.T, method, path string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, p.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Kynotes-Device-Id", p.deviceID)
	req.Header.Set("X-Kynotes-Device-Secret", p.deviceSecret)
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (p *pairClient) mintToken(t *testing.T) string {
	res := p.do(t, http.MethodPost, "/api/v1/devices/pairing-token", nil, true, false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("mint=%d", res.StatusCode)
	}
	var v struct {
		Token    string `json:"token"`
		DeepLink string `json:"deepLink"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	if v.Token == "" || !strings.HasPrefix(v.DeepLink, "kynotes://pair?") {
		t.Fatal("pairing response incomplete")
	}
	return v.Token
}

func (p *pairClient) register(t *testing.T, token string, key []byte) (string, string, int) {
	body := []byte(`{"pairingToken":` + quote(token) + `,"publicKey":` + quote(base64.StdEncoding.EncodeToString(key)) + `,"platform":"unknown","labelCiphertext":""}`)
	res := p.do(t, http.MethodPost, "/api/v1/devices/register", body, false, false)
	var v struct {
		ID          string `json:"deviceId"`
		Secret      string `json:"deviceSecret"`
		Fingerprint string `json:"fingerprint"`
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	_ = json.Unmarshal(data, &v)
	return v.ID, v.Secret, res.StatusCode
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestPairingTokenIsSingleUse(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	token := p.mintToken(t)
	_, _, status := p.register(t, token, bytes.Repeat([]byte{1}, 32))
	if status != http.StatusOK {
		t.Fatalf("first=%d", status)
	}
	_, _, status = p.register(t, token, bytes.Repeat([]byte{2}, 32))
	if status != http.StatusConflict {
		t.Fatalf("replay=%d", status)
	}
}

func TestReplayedPairingTokenIsRejectedAfterNonceConsumed(t *testing.T) {
	TestPairingTokenIsSingleUse(t)
}

func TestPairingDisabledWhenSecretMissingReturns503(t *testing.T) {
	p := newPairClient(t, "")
	res := p.do(t, http.MethodPost, "/api/v1/devices/pairing-token", nil, true, false)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", res.StatusCode)
	}
	res.Body.Close()
}

func TestRegisterRejectsNon32BytePublicKey(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	token := p.mintToken(t)
	_, _, status := p.register(t, token, []byte("short"))
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d", status)
	}
}

func TestFingerprintIsServerComputedNotClientSupplied(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	key := bytes.Repeat([]byte{3}, 32)
	id, _, status := p.register(t, p.mintToken(t), key)
	if status != http.StatusOK || id == "" {
		t.Fatalf("status=%d id=%q", status, id)
	}
	res := p.do(t, http.MethodGet, "/api/v1/devices", nil, false, false)
	defer res.Body.Close()
	var devices []struct {
		Fingerprint string `json:"fingerprint"`
	}
	_ = json.NewDecoder(res.Body).Decode(&devices)
	want := sha256.Sum256(key)
	if len(devices) != 1 || devices[0].Fingerprint != hex.EncodeToString(want[:]) {
		t.Fatal("fingerprint was not server-computed")
	}
}

func TestRePairingSamePublicKeyReusesDeviceRow(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	key := bytes.Repeat([]byte{4}, 32)
	id1, secret1, status := p.register(t, p.mintToken(t), key)
	if status != http.StatusOK {
		t.Fatal(status)
	}
	id2, secret2, status := p.register(t, p.mintToken(t), key)
	if status != http.StatusOK || id1 != id2 || secret1 == secret2 {
		t.Fatalf("re-pair id=%q/%q status=%d", id1, id2, status)
	}
}

func TestDeviceSecretIsReturnedOnceAndNeverAgain(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	_, secret, status := p.register(t, p.mintToken(t), bytes.Repeat([]byte{5}, 32))
	if status != http.StatusOK || secret == "" {
		t.Fatal("registration omitted secret")
	}
	res := p.do(t, http.MethodGet, "/api/v1/devices", nil, false, false)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("device secret returned again")
	}
}

func TestDeviceCannotMintPairingToken(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{6}, 32))
	res := p.doDeviceOnly(t, http.MethodPost, "/api/v1/devices/pairing-token", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", res.StatusCode)
	}
	res.Body.Close()
}

func TestDeviceCannotWriteEnvelopes(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{7}, 32))
	res := p.doDeviceOnly(t, http.MethodPut, "/api/v1/containers/cnt_missing/envelopes", []byte(`{"envelopes":[]}`))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", res.StatusCode)
	}
	res.Body.Close()
}
