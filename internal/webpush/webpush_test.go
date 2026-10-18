package webpush

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseEndpointAcceptsOnlyPushServices(t *testing.T) {
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/abc:def",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
		"https://push.services.mozilla.com/x",
		"https://web.push.apple.com/QGt0",
		"https://wns2-par02p.notify.windows.com/w/?token=AwYAAAB%2b",
	} {
		if _, err := ParseEndpoint(ok); err != nil {
			t.Errorf("refused %s", ok)
		}
	}
	for _, bad := range []string{
		"http://fcm.googleapis.com/fcm/send/x",
		"https://fcm.googleapis.com.evil.com/x",
		"https://evilfcm.googleapis.com/x",
		"https://googleapis.com/x",
		"https://user:pass@fcm.googleapis.com/x",
		"https://user@fcm.googleapis.com/x",
		"https://fcm.googleapis.com:443/x",
		"https://fcm.googleapis.com:8443/x",
		"https://fcm.googleapis.com./x",
		"https://FCM.googleapis.com/x",
		"https://127.0.0.1/x",
		"https://[::1]/x",
		"https://169.254.169.254/latest/meta-data",
		"https://localhost/x",
		"https://notify.windows.com.localhost/x",
		"https://fcm.googleapis.com",
		"https://fcm.googleapis.com/x#frag",
		"https://fcm.googleapis.com\\@evil.com/x",
		"https://evil.com/?https://fcm.googleapis.com/",
		"file:///etc/passwd",
		"https:fcm.googleapis.com/x",
		" https://fcm.googleapis.com/x",
		"https://fcm.googleapis.com/" + strings.Repeat("a", MaxEndpoint),
		"",
	} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func testSender(t *testing.T) *Sender {
	t.Helper()
	key, err := LoadKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadKeyPersistsAndRefusesAGarbledFile(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadKey(dir)
	if err != nil || !a.Equal(b) {
		t.Fatal("the key changed across starts", err)
	}
	path := filepath.Join(dir, "secrets", "vapid.key")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", fi, err)
	}
	if err := os.WriteFile(path, []byte("not base64"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(dir); err == nil {
		t.Fatal("a garbled key file loaded")
	}
}

// verify checks an ES256 JWT against the advertised applicationServerKey and returns its claims.
func verify(t *testing.T, token, publicKey string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != 65 {
		t.Fatalf("public key: %d %v", len(raw), err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %d %v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify with the public key")
	}
	var header map[string]string
	var claims map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil || header["typ"] != "JWT" || header["alg"] != "ES256" || len(header) != 2 {
		t.Fatalf("header %s claims %s", h, c)
	}
	return claims
}

func TestTokenVerifiesWithThePublicKey(t *testing.T) {
	s := testSender(t)
	now := time.Unix(1_800_000_000, 0)
	token, err := s.Token("https://fcm.googleapis.com", now)
	if err != nil {
		t.Fatal(err)
	}
	claims := verify(t, token, s.PublicKey())
	exp := int64(claims["exp"].(float64))
	if claims["aud"] != "https://fcm.googleapis.com" || exp <= now.Unix() || exp > now.Add(12*time.Hour).Unix() || !strings.HasPrefix(claims["sub"].(string), "https://") || len(claims) != 3 {
		t.Fatalf("claims %v", claims)
	}
	// A different key does not verify it.
	other := testSender(t)
	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(other.PublicKey())
	pub, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("another key verified the token")
	}
}

func TestSendIsEmptySignedAndFollowsNoRedirect(t *testing.T) {
	s := testSender(t)
	var got *http.Request
	var body []byte
	redirected := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			redirected = true
			return
		}
		got, body = r, nil
		body, _ = io.ReadAll(r.Body)
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	s.Client = NewClient(srv.Client().Transport)
	s.Allow = func(string) bool { return true }
	now := time.Now()
	if out := s.send(context.Background(), srv.URL+"/push/abc", now); out != delivered {
		t.Fatalf("outcome %d", out)
	}
	if got.Method != http.MethodPost || len(body) != 0 || got.Header.Get("TTL") != "3600" || got.Header.Get("Urgency") != "high" || got.Header.Get("Content-Encoding") != "" {
		t.Fatalf("request %s %q %v", got.Method, body, got.Header)
	}
	auth := got.Header.Get("Authorization")
	token, key, ok := strings.Cut(strings.TrimPrefix(auth, "vapid t="), ", k=")
	if !strings.HasPrefix(auth, "vapid t=") || !ok || key != s.PublicKey() {
		t.Fatalf("authorization %q", auth)
	}
	if claims := verify(t, token, key); claims["aud"] != srv.URL {
		t.Fatalf("aud %v, want the endpoint origin %s", claims["aud"], srv.URL)
	}
	if out := s.send(context.Background(), srv.URL+"/moved", now); out != refused || redirected {
		t.Fatalf("redirect: outcome %d, followed %v", out, redirected)
	}
	// Without the test override the production guard refuses the httptest address outright.
	s.Allow = nil
	got = nil
	if out := s.send(context.Background(), srv.URL+"/push/abc", now); out != refused || got != nil {
		t.Fatalf("an endpoint outside the push services was contacted: %d", out)
	}
}

func TestSendTimesOut(t *testing.T) {
	s := testSender(t)
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	if s.Client.Timeout != Timeout || Timeout != 5*time.Second {
		t.Fatalf("timeout %v", s.Client.Timeout)
	}
	s.Client = NewClient(srv.Client().Transport)
	s.Client.Timeout = 50 * time.Millisecond // the same client, a test-length budget
	s.Allow = func(string) bool { return true }
	if out := s.send(context.Background(), srv.URL+"/slow", time.Now()); out != transient {
		t.Fatalf("outcome %d", out)
	}
}
