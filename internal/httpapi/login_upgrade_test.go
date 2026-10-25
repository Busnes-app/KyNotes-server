package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

// A legacy account (100 000 iterations) is upgraded once, atomically with its password copy,
// without revoking anything; a replay or a second upgrade changes nothing.
func TestLoginUpgradeReplacesALegacyVerifierOnce(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	jar, _ := cookiejar.New(nil)
	other := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url}
	if code, body := status(t, other.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("second session=%d %s", code, body)
	}
	identityID := p.createIdentity(t)
	rewrapped := bytes.Repeat([]byte{6}, wrappedIdentityBytes)
	upgrade := func(current string, iterations string, wrap bool) (int, string) {
		body := `{"currentAuthSecret":"` + current + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":` + iterations
		if wrap {
			body += `,"identityDeviceId":` + quote(identityID) + `,"wrappedIdentityKey":` + quote(base64.StdEncoding.EncodeToString(rewrapped))
		}
		return status(t, p.do(t, http.MethodPost, "/api/v1/auth/login-upgrade", []byte(body+`}`), true, false))
	}
	stored := func() (iterations int, salt string, wrapped []byte) {
		t.Helper()
		if err := p.db.QueryRow(`SELECT u.login_iterations,u.login_salt,i.wrapped_private_key FROM users u JOIN user_identities i ON i.user_id=u.id WHERE u.id=?`, pairUser).Scan(&iterations, &salt, &wrapped); err != nil {
			t.Fatal(err)
		}
		return
	}

	if code, _ := upgrade(strings.Repeat("a", 64), "100000", true); code != http.StatusBadRequest {
		t.Fatalf("upgrade to a legacy count: %d", code)
	}
	if code, body := upgrade(strings.Repeat("a", 64), "600000", false); code != http.StatusConflict || errorCode(t, body) != "identity_rewrap_required" {
		t.Fatalf("upgrade orphaning the password copy: %d %s", code, body)
	}
	if code, _ := upgrade(strings.Repeat("b", 64), "600000", true); code != http.StatusUnauthorized {
		t.Fatalf("wrong current secret: %d", code)
	}
	if n, salt, _ := stored(); n != 100000 || salt == "bmV3c2FsdA==" {
		t.Fatalf("a refused upgrade committed: %d %q", n, salt)
	}

	if code, body := upgrade(strings.Repeat("a", 64), "600000", true); code != http.StatusNoContent {
		t.Fatalf("upgrade=%d %s", code, body)
	}
	if n, salt, wrapped := stored(); n != 600000 || salt != "bmV3c2FsdA==" || !bytes.Equal(wrapped, rewrapped) {
		t.Fatalf("verifier and password copy not upgraded together: %d %q", n, salt)
	}
	// Nothing is revoked: the other session lives on, and the new secret signs in.
	if code, body := status(t, other.do(t, http.MethodGet, "/api/v1/auth/session", nil, false, false)); code != http.StatusOK {
		t.Fatalf("other session after upgrade=%d %s", code, body)
	}
	if code, _ := status(t, other.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"pair","authSecret":"`+strings.Repeat("c", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("login with the upgraded secret=%d", code)
	}

	// A replay after a lost response, or an upgrade from another tab, changes nothing.
	if code, _ := upgrade(strings.Repeat("a", 64), "600000", true); code != http.StatusUnauthorized {
		t.Fatalf("replayed upgrade: %d", code)
	}
	if code, body := upgrade(strings.Repeat("c", 64), "1000000", true); code != http.StatusConflict || errorCode(t, body) != "already_exists" {
		t.Fatalf("second upgrade: %d %s", code, body)
	}
	if n, _, _ := stored(); n != 600000 {
		t.Fatalf("second upgrade committed: %d", n)
	}
	var audits int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='account.login_upgrade'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("upgrade audits=%d %v", audits, err)
	}
}

// Every password write refuses fewer than auth.LoginIterations; only reading an older account accepts them.
func TestPasswordWritesRefuseLegacyIterations(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	body := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":599999}`
	if code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/auth/password", []byte(body), true, false)); code != http.StatusBadRequest {
		t.Fatalf("password change at 599999: %d", code)
	}
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t)
	create := `{"username":"low","authSecret":"` + strings.Repeat("c", 64) + `","loginSalt":"bmV3c2FsdA==","iterations":100000,"accountKind":"user"}`
	if code, _ := status(t, admin.do(t, http.MethodPost, "/api/v1/admin/users", []byte(create), true, false)); code != http.StatusBadRequest {
		t.Fatalf("admin create at 100000: %d", code)
	}
	if auth.LoginIterations != 600000 {
		t.Fatalf("LoginIterations=%d, want the frozen 600000", auth.LoginIterations)
	}
}
