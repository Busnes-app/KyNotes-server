package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

// addUserInOrg creates an everyday account in org (created if missing) and signs it in.
func (p *pairClient) addUserInOrg(t *testing.T, username, org string) member {
	t.Helper()
	if _, err := p.db.Exec(`INSERT INTO orgs(id,status,home_region) VALUES(?,'active','local') ON CONFLICT(id) DO NOTHING`, org); err != nil {
		t.Fatal(err)
	}
	id := mint(t, "usr")
	hash, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := p.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES(?,?,?,?,?,'now','now',?)`, id, username, hash, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 100000, org); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	q := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url, root: p.root}
	if code, body := status(t, q.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":`+quote(username)+`,"authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("login %s=%d %s", username, code, body)
	}
	return member{q, id}
}

// N7: an invitation to another org's account is created as for an unknown ID, and its accept
// answers exactly as a missing invitation's does, leaving no membership.
func TestCrossOrgInviteeIsRefusedAsMissing(t *testing.T) {
	tm := newTeam(t)
	other := tm.owner.addUserInOrg(t, "other-org-member", "org_b")
	code, body := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", []byte(`{"inviteeID":`+quote(other.id)+`,"role":"viewer"}`), true, false))
	if code != http.StatusOK {
		t.Fatalf("invite=%d %s", code, body)
	}
	var inv struct{ ID, Token string }
	if err := json.Unmarshal([]byte(body), &inv); err != nil {
		t.Fatal(err)
	}
	accept := func(id, token string) (int, string) {
		code, body := status(t, other.do(t, http.MethodPost, "/api/v1/invitations/"+id+"/accept", []byte(`{"token":`+quote(token)+`}`), true, false))
		return code, errorCode(t, body)
	}
	gotCode, gotErr := accept(inv.ID, inv.Token)
	wantCode, wantErr := accept(mint(t, "inv"), inv.Token)
	if gotCode != wantCode || gotErr != wantErr || gotCode != http.StatusNotFound {
		t.Fatalf("cross-org accept=%d %s, missing invitation=%d %s", gotCode, gotErr, wantCode, wantErr)
	}
	var n int
	if err := tm.owner.db.QueryRow(`SELECT count(*) FROM memberships WHERE user_id=?`, other.id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("memberships=%d %v", n, err)
	}
}
