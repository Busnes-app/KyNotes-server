package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// member is a second logged-in user on the same server as the pairClient.
type member struct {
	*pairClient
	id string
}

func mint(t *testing.T, prefix string) string {
	t.Helper()
	id, err := ids.Mint(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// addUser creates a local user (login secret "a"*64) and logs it in.
func (p *pairClient) addUser(t *testing.T, username string) member {
	t.Helper()
	id := mint(t, "usr")
	hash, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := p.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?,?,?,?,'now','now')`, id, username, hash, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 100000); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	q := &pairClient{hc: &http.Client{Jar: jar}, db: p.db, url: p.url}
	if code, body := status(t, q.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":`+quote(username)+`,"authSecret":"`+strings.Repeat("a", 64)+`"}`), false, false)); code != http.StatusOK {
		t.Fatalf("login %s=%d %s", username, code, body)
	}
	return member{q, id}
}

// seedContainer inserts a container (child of team when team != "") with the
// given userID→role memberships.
func seedContainer(t *testing.T, p *pairClient, kind, team string, roles map[string]string) string {
	t.Helper()
	cid := mint(t, "cnt")
	if _, err := p.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,team_id,created_at,updated_at) VALUES(?,?,?,?,'now','now')`, cid, kind, pairUser, team); err != nil {
		t.Fatal(err)
	}
	for uid, role := range roles {
		if _, err := p.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,?,'now')`, mint(t, "mem"), cid, uid, role); err != nil {
			t.Fatal(err)
		}
	}
	return cid
}

func envJSON(deviceID string, generation int64, fill byte) string {
	return `{"deviceId":` + quote(deviceID) + `,"keyGeneration":` + strconv.FormatInt(generation, 10) + `,"alg":"x25519-hkdf-sha256-chacha20poly1305","envelope":` + quote(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 93))) + `}`
}

func envelopesBody(items ...string) []byte {
	return []byte(`{"envelopes":[` + strings.Join(items, ",") + `]}`)
}

func rotationBody(expected int64, items ...string) []byte {
	return []byte(`{"expectedGeneration":` + strconv.FormatInt(expected, 10) + `,"envelopes":[` + strings.Join(items, ",") + `]}`)
}

func generationOf(t *testing.T, p *pairClient, cid string) (generation, shared int64) {
	t.Helper()
	if err := p.db.QueryRow(`SELECT key_generation,shared_generation FROM containers WHERE id=?`, cid).Scan(&generation, &shared); err != nil {
		t.Fatal(err)
	}
	return
}

func countEnvelopes(t *testing.T, p *pairClient, cid string, generation int64) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM key_envelopes WHERE container_id=? AND key_generation=?`, cid, generation).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// save creates an object in cid if oid is empty, then PUTs one version at generation.
func (p *pairClient) save(t *testing.T, cid, oid string, generation int64) (string, int) {
	t.Helper()
	if oid == "" {
		res := p.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/objects", []byte(`{"kind":"note"}`), true, false)
		var out struct{ ID string }
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || json.Unmarshal(data, &out) != nil {
			t.Fatalf("create object=%d %s", res.StatusCode, data)
		}
		oid = out.ID
	}
	var base int64
	_ = p.db.QueryRow(`SELECT current_version FROM objects WHERE id=?`, oid).Scan(&base)
	req, _ := http.NewRequest(http.MethodPut, p.url+"/api/v1/objects/"+oid, strings.NewReader("ciphertext"))
	req.Header.Set("X-Kynotes-Key-Generation", strconv.FormatInt(generation, 10))
	req.Header.Set("X-Kynotes-Base-Version", strconv.FormatInt(base, 10))
	for _, c := range p.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := p.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return oid, res.StatusCode
}

func (p *pairClient) comment(t *testing.T, oid string, generation int64) (string, int) {
	t.Helper()
	res := p.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":`+strconv.FormatInt(generation, 10)+`}`), true, false)
	var out struct{ ID string }
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	_ = json.Unmarshal(data, &out)
	return out.ID, res.StatusCode
}

// team is an owner (the pairClient), an admin and an editor, each with an identity,
// plus a viewer without one, in a team with one child workspace.
type team struct {
	owner                      *pairClient
	admin, editor, viewer      member
	ownerID, adminID, editorID string
	id, child                  string
}

func newTeam(t *testing.T) team {
	t.Helper()
	p := newPairClient(t, strings.Repeat("p", 32))
	tm := team{owner: p, admin: p.addUser(t, "admin2"), editor: p.addUser(t, "editor"), viewer: p.addUser(t, "viewer")}
	roles := map[string]string{pairUser: "owner", tm.admin.id: "admin", tm.editor.id: "editor", tm.viewer.id: "viewer"}
	tm.id = seedContainer(t, p, "team", "", roles)
	tm.child = seedContainer(t, p, "workbook", tm.id, roles)
	tm.ownerID = p.createIdentity(t)
	tm.adminID = tm.admin.createIdentity(t)
	tm.editorID = tm.editor.createIdentity(t)
	return tm
}

// rotate mints generation expected+1 for every identity in the team container.
func (tm team) rotate(t *testing.T, cid string, expected int64) {
	t.Helper()
	body := rotationBody(expected, envJSON(tm.ownerID, expected+1, 1), envJSON(tm.adminID, expected+1, 1), envJSON(tm.editorID, expected+1, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate=%d %s", code, out)
	}
}

// send is goroutine-safe: it reports failures instead of calling t.Fatal.
func (p *pairClient) send(method, path string, body []byte) (int, error) {
	req, err := http.NewRequest(method, p.url+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range p.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := p.hc.Do(req)
	if err != nil {
		return 0, err
	}
	res.Body.Close()
	return res.StatusCode, nil
}

// sendRacing sends an authorized request and runs commit after the handler's
// pre-checks, when it first reads the body (Expect: 100-continue).
func (p *pairClient) sendRacing(t *testing.T, method, path string, headers map[string]string, body []byte, commit func()) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, p.url+path, &commitFirst{commit: commit, body: bytes.NewReader(body)})
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Expect", "100-continue")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range p.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := (&http.Client{Transport: &http.Transport{ExpectContinueTimeout: time.Minute}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return status(t, res)
}

func (p *pairClient) saveRacing(t *testing.T, oid string, generation int64, commit func()) int {
	t.Helper()
	var base int64
	_ = p.db.QueryRow(`SELECT current_version FROM objects WHERE id=?`, oid).Scan(&base)
	code, _ := p.sendRacing(t, http.MethodPut, "/api/v1/objects/"+oid, map[string]string{"X-Kynotes-Key-Generation": strconv.FormatInt(generation, 10), "X-Kynotes-Base-Version": strconv.FormatInt(base, 10)}, []byte("ciphertext"), commit)
	return code
}

func TestEnvelopeWriteRequiresUserStepUp(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{7}, 32))
	// The session is seconds old: the retired session-age rule would have admitted it.
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/containers/"+cid+"/envelopes", envelopesBody(envJSON(p.deviceID, 1, 1)), true, false)); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("fresh session without step-up: %d %s", code, body)
	}
	p.stepUp(t)
	if code, _ := status(t, p.do(t, http.MethodPut, "/api/v1/containers/"+cid+"/envelopes", envelopesBody(envJSON(p.deviceID, 1, 1)), false, false)); code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", code)
	}
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/containers/"+cid+"/envelopes", envelopesBody(envJSON(p.deviceID, 1, 1)), true, false)); code != http.StatusNoContent {
		t.Fatalf("after step-up: %d %s", code, body)
	}
}

func TestEnvelopeWriteIsInsertOnlyExceptOwnIdentity(t *testing.T) {
	tm := newTeam(t)
	put := func(c *pairClient, body []byte) (int, string) {
		return status(t, c.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", body, true, false))
	}
	if code, body := put(tm.owner, envelopesBody(envJSON(tm.editorID, 1, 1), envJSON(tm.ownerID, 1, 1))); code != http.StatusNoContent {
		t.Fatalf("first write=%d %s", code, body)
	}
	tm.admin.stepUp(t)
	if code, body := put(tm.admin.pairClient, envelopesBody(envJSON(tm.editorID, 1, 2))); code != http.StatusConflict || !strings.Contains(body, "already_exists") {
		t.Fatalf("second steward overwrote a recipient: %d %s", code, body)
	}
	var fill []byte
	if err := tm.owner.db.QueryRow(`SELECT envelope FROM key_envelopes WHERE device_id=?`, tm.editorID).Scan(&fill); err != nil || fill[0] != 1 {
		t.Fatalf("envelope changed: %x %v", fill, err)
	}
	if code, body := put(tm.owner, envelopesBody(envJSON(tm.ownerID, 1, 3))); code != http.StatusNoContent {
		t.Fatalf("own identity replace=%d %s", code, body)
	}
	if err := tm.owner.db.QueryRow(`SELECT envelope FROM key_envelopes WHERE device_id=?`, tm.ownerID).Scan(&fill); err != nil || fill[0] != 3 {
		t.Fatalf("own identity not replaced: %x %v", fill, err)
	}
}

func TestMemberMayWriteOnlyOwnEnvelopes(t *testing.T) {
	tm := newTeam(t)
	ed := tm.editor
	ed.deviceID, ed.deviceSecret, _ = ed.register(t, ed.mintToken(t), bytes.Repeat([]byte{8}, 32))
	ed.stepUp(t)
	put := func(body []byte) (int, string) {
		return status(t, ed.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", body, true, false))
	}
	// The first identity envelope comes from a steward; the member may then re-wrap it.
	if code, body := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(tm.editorID, 1, 1)), true, false)); code != http.StatusNoContent {
		t.Fatalf("steward wrap for editor=%d %s", code, body)
	}
	if code, body := put(envelopesBody(envJSON(tm.editorID, 1, 1), envJSON(ed.deviceID, 1, 1))); code != http.StatusNoContent {
		t.Fatalf("own identity and phone=%d %s", code, body)
	}
	if code, body := put(envelopesBody(envJSON(tm.adminID, 1, 1))); code != http.StatusForbidden || !strings.Contains(body, "forbidden") {
		t.Fatalf("editor wrapped for another member: %d %s", code, body)
	}
	if n := countEnvelopes(t, tm.owner, tm.id, 1); n != 2 {
		t.Fatalf("envelopes=%d, want 2", n)
	}
}

func TestOwnIdentityWriteIsRewrapOnly(t *testing.T) {
	tm := newTeam(t)
	ed := tm.editor
	ed.stepUp(t)
	path := "/api/v1/containers/" + tm.id + "/envelopes"
	if code, body := status(t, ed.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false)); code != http.StatusForbidden || !strings.Contains(body, "forbidden") {
		t.Fatalf("member minted its own first identity envelope: %d %s", code, body)
	}
	if n := countEnvelopes(t, tm.owner, tm.id, 1); n != 0 {
		t.Fatalf("envelopes=%d, want 0", n)
	}
	if code, body := status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false)); code != http.StatusNoContent {
		t.Fatalf("steward wrap=%d %s", code, body)
	}
	if code, body := status(t, ed.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 2)), true, false)); code != http.StatusNoContent {
		t.Fatalf("member re-wrap=%d %s", code, body)
	}
	var fill []byte
	if err := tm.owner.db.QueryRow(`SELECT envelope FROM key_envelopes WHERE device_id=?`, tm.editorID).Scan(&fill); err != nil || fill[0] != 2 {
		t.Fatalf("re-wrap not stored: %x %v", fill, err)
	}
}

func TestEnvelopeWriteRefusals(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, tm team, path string) (int, string)
		code int
		want string
	}{
		{"non-member caller", func(t *testing.T, tm team, path string) (int, string) {
			out := tm.owner.addUser(t, "outsider")
			out.stepUp(t)
			return status(t, out.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.ownerID, 1, 1)), true, false))
		}, http.StatusNotFound, "not_found"},
		{"revoked caller membership", func(t *testing.T, tm team, path string) (int, string) {
			tm.admin.stepUp(t)
			if _, err := tm.owner.db.Exec(`UPDATE memberships SET revoked_at='now' WHERE container_id=? AND user_id=?`, tm.id, tm.admin.id); err != nil {
				t.Fatal(err)
			}
			return status(t, tm.admin.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false))
		}, http.StatusNotFound, "not_found"},
		{"revoked recipient device", func(t *testing.T, tm team, path string) (int, string) {
			if _, err := tm.owner.db.Exec(`UPDATE devices SET revoked_at='now' WHERE id=?`, tm.editorID); err != nil {
				t.Fatal(err)
			}
			return status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false))
		}, http.StatusBadRequest, "invalid_request"},
		{"non-member recipient", func(t *testing.T, tm team, path string) (int, string) {
			outsiderID := tm.owner.addUser(t, "outsider").createIdentity(t)
			return status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(outsiderID, 1, 1)), true, false))
		}, http.StatusBadRequest, "invalid_request"},
		{"inactive recipient user", func(t *testing.T, tm team, path string) (int, string) {
			if _, err := tm.owner.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, tm.editor.id); err != nil {
				t.Fatal(err)
			}
			return status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false))
		}, http.StatusBadRequest, "invalid_request"},
		{"stale generation", func(t *testing.T, tm team, path string) (int, string) {
			return status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 2, 1)), true, false))
		}, http.StatusConflict, "already_exists"},
		{"SSO session", func(t *testing.T, tm team, path string) (int, string) {
			if _, err := tm.owner.db.Exec(`UPDATE sessions SET sso_issuer='https://idp.example' WHERE user_id=?`, pairUser); err != nil {
				t.Fatal(err)
			}
			return status(t, tm.owner.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false))
		}, http.StatusForbidden, "step_up_required"},
		{"device credential", func(t *testing.T, tm team, path string) (int, string) {
			p := tm.owner
			p.deviceID, p.deviceSecret, _ = p.register(t, p.mintToken(t), bytes.Repeat([]byte{7}, 32))
			return status(t, p.doDeviceOnly(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1))))
		}, http.StatusUnauthorized, "unauthenticated"},
		{"password change after middleware", func(t *testing.T, tm team, path string) (int, string) {
			changed := 0
			code, body := tm.owner.sendRacing(t, http.MethodPut, path, map[string]string{"Content-Type": "application/json"}, envelopesBody(envJSON(tm.editorID, 1, 1)), func() {
				change := `{"currentAuthSecret":"` + strings.Repeat("a", 64) + `","newAuthSecret":"` + strings.Repeat("c", 64) + `","newLoginSalt":"bmV3c2FsdA==","iterations":100000,"wrappedIdentityKey":` + quote(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, wrappedIdentityBytes))) + `,"identityDeviceId":` + quote(tm.ownerID) + `}`
				changed, _ = tm.owner.send(http.MethodPost, "/api/v1/auth/password", []byte(change))
			})
			if changed != http.StatusNoContent {
				t.Fatalf("password change=%d", changed)
			}
			return code, body
		}, http.StatusForbidden, "step_up_required"},
		{"non-steward for another member", func(t *testing.T, tm team, path string) (int, string) {
			tm.editor.stepUp(t)
			return status(t, tm.editor.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.adminID, 1, 1)), true, false))
		}, http.StatusForbidden, "forbidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tm := newTeam(t)
			if code, body := c.run(t, tm, "/api/v1/containers/"+tm.id+"/envelopes"); code != c.code || !strings.Contains(body, `"`+c.want+`"`) {
				t.Fatalf("got %d %s, want %d %s", code, body, c.code, c.want)
			}
			if n := countEnvelopes(t, tm.owner, tm.id, 1) + countEnvelopes(t, tm.owner, tm.id, 2); n != 0 {
				t.Fatalf("refused write stored %d envelopes", n)
			}
		})
	}
}
