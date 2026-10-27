package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"
)

// Login and back-channel logout each build their own verifier from a cold cache; both must
// refuse an identity provider whose JWKS holds an RSA key below 2048 bits.
func TestSSOLoginAndLogoutRefuseUndersizedJWKSKeys(t *testing.T) {
	for _, bits := range []int{1024, 2047, 2048} {
		f := newLogoutFixture(t)
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.key, f.keyID, f.jwksPath = key, "sized", "/rotated-keys"
		f.mu.Unlock()
		f.restartRouter()
		strong := bits >= 2048

		res := f.send(f.beginLogin("alice", "sized", time.Now()))
		if (res.Code == http.StatusFound) != strong {
			t.Fatalf("RSA-%d login: %d %s", bits, res.Code, res.Body.String())
		}
		var sessions int
		if err := f.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE sso_issuer<>''`).Scan(&sessions); err != nil || (sessions == 1) != strong {
			t.Fatalf("RSA-%d login sessions: %d %v", bits, sessions, err)
		}

		f.restartRouter()
		if res := f.logout(f.sign("logout+jwt", f.logoutClaims("sized", "alice", "sized"))); (res.Code == http.StatusOK) != strong {
			t.Fatalf("RSA-%d logout: %d %s", bits, res.Code, res.Body.String())
		}
	}
}
