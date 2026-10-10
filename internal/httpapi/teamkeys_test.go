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
	"sync"
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

// addAdmin creates an administrator account (login secret "a"*64) and signs it in. It can hold
// no content: tests that need an administrator and a member use two accounts.
func (p *pairClient) addAdmin(t *testing.T, username string) member {
	t.Helper()
	id := mint(t, "usr")
	hash, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := p.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,?,?,?,'admin','admin','now','now')`, id, username, hash, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 100000); err != nil {
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
	req.Header.Set(keySchemeHeader, keySchemeShared)
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
	req.Header.Set(keySchemeHeader, keySchemeShared) // a current web client
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
	code, _ := p.sendRacing(t, http.MethodPut, "/api/v1/objects/"+oid, map[string]string{"X-Kynotes-Key-Generation": strconv.FormatInt(generation, 10), "X-Kynotes-Base-Version": strconv.FormatInt(base, 10), keySchemeHeader: keySchemeShared}, []byte("ciphertext"), commit)
	return code
}

func TestEnvelopeWriteRequiresUserStepUp(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	keyForTest(t, p.db, cid, pairUser)
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
	keyForTest(t, tm.owner.db, tm.id, pairUser)
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
	keyForTest(t, tm.owner.db, tm.id, pairUser)
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
	if n := countEnvelopes(t, tm.owner, tm.id, 1); n != 3 {
		t.Fatalf("envelopes=%d, want the owner's, the editor's identity and phone", n)
	}
}

func TestOwnIdentityWriteIsRewrapOnly(t *testing.T) {
	tm := newTeam(t)
	keyForTest(t, tm.owner.db, tm.id, pairUser)
	ed := tm.editor
	ed.stepUp(t)
	path := "/api/v1/containers/" + tm.id + "/envelopes"
	if code, body := status(t, ed.do(t, http.MethodPut, path, envelopesBody(envJSON(tm.editorID, 1, 1)), true, false)); code != http.StatusForbidden || !strings.Contains(body, "forbidden") {
		t.Fatalf("member minted its own first identity envelope: %d %s", code, body)
	}
	if n := countEnvelopes(t, tm.owner, tm.id, 1); n != 1 {
		t.Fatalf("envelopes=%d, want the owner's only", n)
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
		}, http.StatusForbidden, "sso_step_up_required"},
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
			keyForTest(t, tm.owner.db, tm.id, pairUser)
			if code, body := c.run(t, tm, "/api/v1/containers/"+tm.id+"/envelopes"); code != c.code || !strings.Contains(body, `"`+c.want+`"`) {
				t.Fatalf("got %d %s, want %d %s", code, body, c.code, c.want)
			}
			if n := countEnvelopes(t, tm.owner, tm.id, 1) + countEnvelopes(t, tm.owner, tm.id, 2); n != 1 {
				t.Fatalf("refused write stored %d envelopes beside the owner's", n-1)
			}
		})
	}
}

func TestKeyRotationIsAtomicAndCoversEveryIdentity(t *testing.T) {
	tm := newTeam(t)
	path := "/api/v1/containers/" + tm.id + "/key-rotations"
	full := rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1))
	tm.editor.stepUp(t)
	solo := seedContainer(t, tm.owner, "workbook", "", map[string]string{tm.editor.id: "editor", tm.viewer.id: "owner"})
	if code, body := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/containers/"+solo+"/key-rotations", rotationBody(1, envJSON(tm.editorID, 2, 1)), true, false)); code != http.StatusForbidden {
		t.Fatalf("editor rotated: %d %s", code, body)
	}
	// A steward without an identity cannot mint a key it could never hold.
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='admin' WHERE user_id=?`, tm.viewer.id); err != nil {
		t.Fatal(err)
	}
	tm.viewer.stepUp(t)
	if code, body := status(t, tm.viewer.do(t, http.MethodPost, path, full, true, false)); code != http.StatusBadRequest {
		t.Fatalf("steward without identity rotated: %d %s", code, body)
	}
	for name, body := range map[string][]byte{
		"missing a member identity": rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.adminID, 2, 1)),
		"missing the caller":        rotationBody(1, envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1)),
		"wrong generation":          rotationBody(1, envJSON(tm.ownerID, 3, 1), envJSON(tm.adminID, 3, 1), envJSON(tm.editorID, 3, 1)),
		"duplicate recipient":       rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.ownerID, 2, 2), envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1)),
	} {
		if code, out := status(t, tm.owner.do(t, http.MethodPost, path, body, true, false)); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, code, out)
		}
		if g, _ := generationOf(t, tm.owner, tm.id); g != 1 || countEnvelopes(t, tm.owner, tm.id, 2) != 0 {
			t.Fatalf("%s: partial commit at generation %d", name, g)
		}
	}
	if code, body := status(t, tm.owner.do(t, http.MethodPost, path, full, true, false)); code != http.StatusOK || !strings.Contains(body, `"keyGeneration":2`) {
		t.Fatalf("full set=%d %s", code, body)
	}
	if g, shared := generationOf(t, tm.owner, tm.id); g != 2 || shared != 2 || countEnvelopes(t, tm.owner, tm.id, 2) != 3 {
		t.Fatalf("after rotation generation=%d shared=%d", g, shared)
	}
	if code, body := status(t, tm.owner.do(t, http.MethodPost, path, full, true, false)); code != http.StatusConflict {
		t.Fatalf("stale expectedGeneration=%d %s", code, body)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.key_rotate' AND container_id=?`, tm.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d %v", audits, err)
	}
	tm.rotate(t, tm.id, 2)
	if g, shared := generationOf(t, tm.owner, tm.id); g != 3 || shared != 2 {
		t.Fatalf("second rotation moved shared_generation: generation=%d shared=%d", g, shared)
	}
}

func TestKeyRotationRequiresUserStepUp(t *testing.T) {
	tm := newTeam(t)
	if _, err := tm.owner.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
		t.Fatal(err)
	}
	body := rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusForbidden || !strings.Contains(out, "step_up_required") {
		t.Fatalf("rotation without step-up: %d %s", code, out)
	}
}

func TestConcurrentRotationsCannotSplitAGeneration(t *testing.T) {
	tm := newTeam(t)
	tm.admin.stepUp(t)
	path := "/api/v1/containers/" + tm.id + "/key-rotations"
	codes := make([]int, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, c := range []*pairClient{tm.owner, tm.admin.pairClient} {
		wg.Add(1)
		go func(i int, c *pairClient) {
			defer wg.Done()
			fill := byte(10 + i)
			codes[i], errs[i] = c.send(http.MethodPost, path, rotationBody(1, envJSON(tm.ownerID, 2, fill), envJSON(tm.adminID, 2, fill), envJSON(tm.editorID, 2, fill)))
		}(i, c)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatal(errs)
	}
	if codes[0]+codes[1] != http.StatusOK+http.StatusConflict {
		t.Fatalf("codes=%v, want one 200 and one 409", codes)
	}
	var keys int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(DISTINCT envelope) FROM key_envelopes WHERE container_id=? AND key_generation=2`, tm.id).Scan(&keys); err != nil || keys != 1 {
		t.Fatalf("generation 2 holds %d distinct keys: %v", keys, err)
	}
	if g, _ := generationOf(t, tm.owner, tm.id); g != 2 {
		t.Fatalf("generation=%d", g)
	}
}

func TestEnvelopeForNonMemberIsRejected(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	outsider := tm.owner.addUser(t, "outsider")
	outsiderID := outsider.createIdentity(t)
	if code, body := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(outsiderID, 2, 1)), true, false)); code != http.StatusBadRequest {
		t.Fatalf("PUT for non-member=%d %s", code, body)
	}
	body := rotationBody(2, envJSON(tm.ownerID, 3, 1), envJSON(tm.adminID, 3, 1), envJSON(tm.editorID, 3, 1), envJSON(outsiderID, 3, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusBadRequest {
		t.Fatalf("rotation with non-member=%d %s", code, out)
	}
	if g, shared := generationOf(t, tm.owner, tm.id); g != 2 || shared != 2 || countEnvelopes(t, tm.owner, tm.id, 3) != 0 {
		t.Fatalf("refused rotation left state: generation=%d shared=%d", g, shared)
	}
	// A removed member is a non-member too.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(envJSON(tm.editorID, 2, 1)), true, false)); code != http.StatusBadRequest {
		t.Fatalf("PUT for removed member=%d %s", code, out)
	}
}

func TestEnvelopeWritesRecheckStepUpInTransaction(t *testing.T) {
	tm := newTeam(t)
	clear := func() {
		if _, err := tm.owner.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
			t.Error(err)
		}
	}
	hdr := map[string]string{"Content-Type": "application/json"}
	if code, body := tm.owner.sendRacing(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", hdr, envelopesBody(envJSON(tm.editorID, 1, 1)), clear); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("envelope PUT after step-up was cleared: %d %s", code, body)
	}
	tm.owner.stepUp(t)
	rotation := rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1))
	if code, body := tm.owner.sendRacing(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", hdr, rotation, clear); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("rotation after step-up was cleared: %d %s", code, body)
	}
	if g, _ := generationOf(t, tm.owner, tm.id); g != 1 || countEnvelopes(t, tm.owner, tm.id, 1) != 0 {
		t.Fatalf("stale step-up wrote: generation=%d", g)
	}
}

func TestNewContentRefusedUntilRotationEnvelopesExist(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	tm.rotate(t, tm.id, 2)
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusConflict {
		t.Fatalf("save at the old generation=%d", code)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 3); code != http.StatusOK {
		t.Fatalf("enveloped writer=%d", code)
	}
	// The removal bumps to 4 with no envelopes: no one writes until a steward rotates.
	if code, body := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.admin.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, body)
	}
	for name, code := range map[string]int{
		"save":    func() int { _, c := tm.editor.save(t, tm.id, oid, 4); return c }(),
		"comment": func() int { _, c := tm.editor.comment(t, oid, 4); return c }(),
		"upload":  func() int { return tm.editor.attach(t, tm.id, 4) }(),
	} {
		if code != http.StatusConflict {
			t.Fatalf("%s without an envelope=%d", name, code)
		}
	}
	body := rotationBody(4, envJSON(tm.ownerID, 5, 1), envJSON(tm.editorID, 5, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate after removal=%d %s", code, out)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 5); code != http.StatusOK {
		t.Fatalf("save after re-wrap=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 5); code != http.StatusOK {
		t.Fatalf("upload after re-wrap=%d", code)
	}
	var author string
	if err := tm.owner.db.QueryRow(`SELECT author_user_id FROM object_versions WHERE object_id=? ORDER BY version DESC LIMIT 1`, oid).Scan(&author); err != nil || author != tm.editor.id {
		t.Fatalf("author=%q %v", author, err)
	}
}

func TestSaveRacingRemovalOrRotationIsRefused(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	tm.rotate(t, tm.id, 2)
	rotated := 0
	if code := tm.editor.saveRacing(t, oid, 3, func() {
		rotated, _ = tm.owner.send(http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", rotationBody(3, envJSON(tm.ownerID, 4, 1), envJSON(tm.adminID, 4, 1), envJSON(tm.editorID, 4, 1)))
	}); rotated != http.StatusOK || code != http.StatusConflict {
		t.Fatalf("save racing a rotation: rotate=%d save=%d", rotated, code)
	}
	removed := 0
	if code := tm.editor.saveRacing(t, oid, 4, func() {
		removed, _ = tm.owner.send(http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil)
	}); removed != http.StatusNoContent || code != http.StatusNotFound {
		t.Fatalf("save racing a removal: remove=%d save=%d", removed, code)
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id=?`, oid).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("versions=%d %v", versions, err)
	}
}

// attach uploads a 4-byte attachment into cid and finalizes it at generation.
func (p *pairClient) attach(t *testing.T, cid string, generation int64) int {
	t.Helper()
	res := p.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/uploads", []byte(`{"declaredBytes":4,"kind":"attachment"}`), true, false)
	var up struct {
		ID string `json:"uploadId"`
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || json.Unmarshal(data, &up) != nil {
		t.Fatalf("upload create=%d %s", res.StatusCode, data)
	}
	if code, body := p.sendRacing(t, http.MethodPatch, "/api/v1/uploads/"+up.ID, map[string]string{"X-Kynotes-Chunk-Index": "0", keySchemeHeader: keySchemeShared}, []byte("abcd"), func() {}); code != http.StatusOK {
		t.Fatalf("chunk=%d %s", code, body)
	}
	code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/uploads/"+up.ID+"/finalize", []byte(`{"metadataCiphertext":"","keyGeneration":`+strconv.FormatInt(generation, 10)+`}`), true, false))
	return code
}

func TestRevokedIdentityNeitherWritesNorBlocksRotation(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	if _, err := tm.owner.db.Exec(`UPDATE devices SET revoked_at='2026-10-07T00:00:00Z' WHERE id=?`, tm.editorID); err != nil {
		t.Fatal(err)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusConflict {
		t.Fatalf("revoked identity saved: %d", code)
	}
	body := rotationBody(2, envJSON(tm.ownerID, 3, 1), envJSON(tm.adminID, 3, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("revoked identity blocked rotation: %d %s", code, out)
	}
}

func TestSaveRacingDemotionIsRefused(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	if code := tm.editor.saveRacing(t, oid, 2, func() {
		if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='viewer' WHERE container_id=? AND user_id=?`, tm.id, tm.editor.id); err != nil {
			t.Error(err)
		}
	}); code != http.StatusForbidden {
		t.Fatalf("save racing a demotion=%d", code)
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id=?`, oid).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("versions=%d %v", versions, err)
	}
}

func TestAdminMemberRemovalRotatesLikeOwnerRemoval(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	admin := tm.owner.addAdmin(t, "server-admin")
	if code, body := status(t, admin.do(t, http.MethodDelete, "/api/v1/admin/teams/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("admin remove=%d %s", code, body)
	}
	if g, _ := generationOf(t, tm.owner, tm.id); g != 3 {
		t.Fatalf("team generation=%d, want 3", g)
	}
	if g, _ := generationOf(t, tm.owner, tm.child); g != 2 {
		t.Fatalf("child generation=%d, want 2", g)
	}
	var memberships, envelopes, audits int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM memberships WHERE user_id=?1 AND revoked_at=''),(SELECT COUNT(*) FROM key_envelopes WHERE device_id=?2),(SELECT COUNT(*) FROM audit_events WHERE event='admin.team.member_remove' AND object_id=?1)`, tm.editor.id, tm.editorID).Scan(&memberships, &envelopes, &audits); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 || envelopes != 0 || audits != 1 {
		t.Fatalf("memberships=%d envelopes=%d audits=%d", memberships, envelopes, audits)
	}
	if code, _ := status(t, admin.do(t, http.MethodDelete, "/api/v1/admin/teams/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNotFound {
		t.Fatalf("second removal=%d", code)
	}
	if code, _ := status(t, admin.do(t, http.MethodDelete, "/api/v1/admin/teams/"+tm.id+"/members/"+pairUser, nil, true, false)); code != http.StatusBadRequest {
		t.Fatalf("invalid user ID=%d", code)
	}
}

func TestRemovedMemberCannotWriteAnywhereInTheTeam(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.child, 1)
	oid, _ := tm.editor.save(t, tm.child, "", 2)
	if code, body := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.editor.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, body)
	}
	g, _ := generationOf(t, tm.owner, tm.child)
	if _, code := tm.editor.save(t, tm.child, oid, g); code != http.StatusNotFound {
		t.Fatalf("removed member saved in the child workspace: %d", code)
	}
	if err := checkWriteGate(tm.owner.db, tm.child, tm.editor.id, g, keySchemeShared); err != errNotMember {
		t.Fatalf("gate admitted a removed member (upload finalize path): %v", err)
	}
}

func TestInvitationEnvelopesMoveOnlyAtTheirGeneration(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	body := rotationBody(1, envJSON(tm.ownerID, 2, 1), envJSON(tm.adminID, 2, 1), envJSON(tm.editorID, 2, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.child+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate child=%d %s", code, out)
	}
	invite := func(invitee string, envelopes ...string) (string, string, int) {
		res := tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", []byte(`{"inviteeId":`+quote(invitee)+`,"role":"editor","envelopes":[`+strings.Join(envelopes, ",")+`]}`), true, false)
		var out struct{ ID, Token string }
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		_ = json.Unmarshal(data, &out)
		return out.ID, out.Token, res.StatusCode
	}
	withContainer := func(cid, env string) string { return `{"containerId":` + quote(cid) + `,` + env[1:] }
	fresh, stale := tm.owner.addUser(t, "fresh"), tm.owner.addUser(t, "stale")
	freshID, staleID := fresh.createIdentity(t), stale.createIdentity(t)

	if _, _, code := invite(fresh.id, withContainer(tm.id, envJSON(freshID, 1, 1))); code != http.StatusConflict {
		t.Fatalf("envelope at a past generation=%d", code)
	}
	if _, _, code := invite(fresh.id, withContainer(tm.id, envJSON(staleID, 2, 1))); code != http.StatusBadRequest {
		t.Fatalf("envelope for someone other than the invitee=%d", code)
	}
	if _, _, code := invite(fresh.id, withContainer(tm.id, envJSON(freshID, 2, 1)), withContainer(tm.id, envJSON(freshID, 2, 2))); code != http.StatusBadRequest {
		t.Fatalf("two envelopes for one container=%d", code)
	}
	inv, tok, code := invite(fresh.id, withContainer(tm.id, envJSON(freshID, 2, 1)), withContainer(tm.child, envJSON(freshID, 2, 1)))
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	staleInv, staleTok, code := invite(stale.id, withContainer(tm.id, envJSON(staleID, 2, 1)), withContainer(tm.child, envJSON(staleID, 2, 1)))
	if code != http.StatusOK {
		t.Fatalf("invite stale=%d", code)
	}
	if code, body := status(t, fresh.do(t, http.MethodPost, "/api/v1/invitations/"+inv+"/accept", []byte(`{"token":`+quote(tok)+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("accept=%d %s", code, body)
	}
	if countEnvelopes(t, tm.owner, tm.id, 2) != 4 || countEnvelopes(t, tm.owner, tm.child, 2) != 4 {
		t.Fatal("accepted envelopes were not installed in the team and child")
	}
	if _, code := fresh.save(t, tm.child, "", 2); code != http.StatusOK {
		t.Fatalf("invitee save after accept=%d", code)
	}
	// The team rotates before the second invitee accepts: its team envelope is dropped.
	body = rotationBody(2, envJSON(tm.ownerID, 3, 1), envJSON(tm.adminID, 3, 1), envJSON(tm.editorID, 3, 1), envJSON(freshID, 3, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate team=%d %s", code, out)
	}
	var pending int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM invitation_envelopes WHERE invitation_id=?`, staleInv).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("rotation left stale invitation envelopes: %d %v", pending, err)
	}
	if code, body := status(t, stale.do(t, http.MethodPost, "/api/v1/invitations/"+staleInv+"/accept", []byte(`{"token":`+quote(staleTok)+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("accept stale=%d %s", code, body)
	}
	var teamStale, childStale, left int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM key_envelopes WHERE device_id=?1 AND container_id=?2),(SELECT COUNT(*) FROM key_envelopes WHERE device_id=?1 AND container_id=?3),(SELECT COUNT(*) FROM invitation_envelopes)`, staleID, tm.id, tm.child).Scan(&teamStale, &childStale, &left); err != nil {
		t.Fatal(err)
	}
	if teamStale != 0 || childStale != 1 || left != 0 {
		t.Fatalf("stale team envelope installed=%d, child=%d, leftover=%d", teamStale, childStale, left)
	}
}

func TestUserIdentityVisibility(t *testing.T) {
	tm := newTeam(t)
	get := func(c *pairClient, uid string) (int, string) {
		return status(t, c.do(t, http.MethodGet, "/api/v1/users/"+uid+"/identity", nil, false, false))
	}
	if code, body := get(tm.viewer.pairClient, tm.editor.id); code != http.StatusOK || !strings.Contains(body, tm.editorID) || !strings.Contains(body, `"fingerprint"`) || strings.Contains(body, "wrapped") {
		t.Fatalf("co-member=%d %s", code, body)
	}
	if code, _ := get(tm.editor.pairClient, tm.viewer.id); code != http.StatusNotFound {
		t.Fatalf("member without identity=%d", code)
	}
	stranger := tm.owner.addUser(t, "stranger")
	stranger.createIdentity(t)
	if code, _ := get(tm.editor.pairClient, stranger.id); code != http.StatusNotFound {
		t.Fatalf("editor saw a stranger: %d", code)
	}
	if code, _ := get(tm.owner, stranger.id); code != http.StatusNotFound {
		t.Fatalf("steward resolved a stranger before inviting them: %d", code)
	}
	// A fresh workbook owner is a steward of a solo container: still no lookup, even after inviting.
	loner := tm.owner.addUser(t, "loner")
	if code, out := status(t, loner.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false)); code != http.StatusOK {
		t.Fatalf("create workbook=%d %s", code, out)
	}
	var book string
	if err := tm.owner.db.QueryRow(`SELECT id FROM containers WHERE owner_user_id=?`, loner.id).Scan(&book); err != nil {
		t.Fatal(err)
	}
	if _, code := invite(t, loner.pairClient, book, stranger.id); code != http.StatusOK {
		t.Fatalf("workbook invite=%d", code)
	}
	if code, _ := get(loner.pairClient, stranger.id); code != http.StatusNotFound {
		t.Fatalf("workbook owner resolved a stranger: %d", code)
	}
	if _, code := invite(t, tm.owner, tm.id, stranger.id); code != http.StatusOK {
		t.Fatalf("team invite=%d", code)
	}
	if code, _ := get(tm.owner, stranger.id); code != http.StatusOK {
		t.Fatalf("inviting steward could not resolve the invitee: %d", code)
	}
	if code, _ := get(tm.admin.pairClient, stranger.id); code != http.StatusNotFound {
		t.Fatalf("another steward resolved someone else's invitee: %d", code)
	}
	// A pending invitation stops resolving once its inviter is no longer a steward.
	if _, code := invite(t, tm.admin.pairClient, tm.id, stranger.id); code != http.StatusOK {
		t.Fatalf("admin invite=%d", code)
	}
	if code, _ := get(tm.admin.pairClient, stranger.id); code != http.StatusOK {
		t.Fatalf("inviting admin could not resolve the invitee: %d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='editor' WHERE container_id=? AND user_id=?`, tm.id, tm.admin.id); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(tm.admin.pairClient, stranger.id); code != http.StatusNotFound {
		t.Fatalf("demoted inviter resolved the invitee: %d", code)
	}
	if code, _ := get(stranger.pairClient, tm.editor.id); code != http.StatusNotFound {
		t.Fatalf("stranger without a container saw a user: %d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE devices SET revoked_at='2026-10-07T00:00:00Z' WHERE id=?`, tm.adminID); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(tm.viewer.pairClient, tm.admin.id); code != http.StatusNotFound {
		t.Fatalf("revoked identity visible: %d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, tm.editor.id); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(tm.viewer.pairClient, tm.editor.id); code != http.StatusNotFound {
		t.Fatalf("disabled user visible: %d", code)
	}
	if code, _ := get(tm.viewer.pairClient, "usr_bad"); code != http.StatusBadRequest {
		t.Fatalf("invalid ID: %d", code)
	}
	tm.viewer.deviceID, tm.viewer.deviceSecret, _ = tm.viewer.register(t, tm.viewer.mintToken(t), bytes.Repeat([]byte{6}, 32))
	if res := tm.viewer.doDeviceOnly(t, http.MethodGet, "/api/v1/users/"+tm.admin.id+"/identity", nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device credential=%d", res.StatusCode)
	}
}

// invite creates an admin invitation without envelopes and returns its ID and token.
func invite(t *testing.T, p *pairClient, cid, invitee string) ([2]string, int) {
	t.Helper()
	res := p.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/invitations", []byte(`{"inviteeId":`+quote(invitee)+`,"role":"admin"}`), true, false)
	var out struct{ ID, Token string }
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	_ = json.Unmarshal(data, &out)
	return [2]string{out.ID, out.Token}, res.StatusCode
}

func accept(t *testing.T, p *pairClient, inv [2]string) int {
	t.Helper()
	code, _ := status(t, p.do(t, http.MethodPost, "/api/v1/invitations/"+inv[0]+"/accept", []byte(`{"token":`+quote(inv[1])+`}`), true, false))
	return code
}

func TestInvitationsDieWithTheirStewardship(t *testing.T) {
	tm := newTeam(t)
	removed, demoted := tm.owner.addUser(t, "removed"), tm.owner.addUser(t, "demoted")
	removedID := removed.createIdentity(t)
	inv, code := invite(t, tm.admin.pairClient, tm.id, removed.id)
	if code != http.StatusOK {
		t.Fatalf("invite=%d", code)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES(?,?,?,1,?,x'01')`, inv[0], tm.id, removedID, envelopeAlg); err != nil {
		t.Fatal(err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.admin.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, out)
	}
	var invitations, envelopes int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM invitations WHERE inviter_id=?),(SELECT COUNT(*) FROM invitation_envelopes)`, tm.admin.id).Scan(&invitations, &envelopes); err != nil || invitations != 0 || envelopes != 0 {
		t.Fatalf("removed steward's invitations=%d envelopes=%d %v", invitations, envelopes, err)
	}
	if code := accept(t, removed.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("accepted a removed steward's invitation: %d", code)
	}
	inv, _ = invite(t, tm.editor.pairClient, tm.id, demoted.id)
	if inv[0] != "" {
		t.Fatal("editor invited")
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='admin' WHERE container_id=? AND user_id=?`, tm.id, tm.editor.id); err != nil {
		t.Fatal(err)
	}
	inv, _ = invite(t, tm.editor.pairClient, tm.id, demoted.id)
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='editor' WHERE container_id=? AND user_id=?`, tm.id, tm.editor.id); err != nil {
		t.Fatal(err)
	}
	if code := accept(t, demoted.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("accepted a demoted steward's invitation: %d", code)
	}
	var members int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id IN (?,?)`, removed.id, demoted.id).Scan(&members); err != nil || members != 0 {
		t.Fatalf("memberships=%d %v", members, err)
	}
}

func TestCollaboratorRemovalRulesAndAcceptOutcomes(t *testing.T) {
	tm := newTeam(t)
	other := tm.owner.addUser(t, "admin3")
	if _, err := tm.owner.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'admin','2026-10-07T00:00:00Z')`, mint(t, "mem"), tm.id, other.id); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, tm.admin.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+other.id, nil, true, false)); code != http.StatusForbidden {
		t.Fatalf("admin removed an admin: %d", code)
	}
	if code, out := status(t, tm.admin.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.viewer.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("admin removed a viewer: %d %s", code, out)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='container.member_remove' AND object_id=? AND actor_user_id=?`, tm.viewer.id, tm.admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d %v", audits, err)
	}
	guest := tm.owner.addUser(t, "guest")
	inv, _ := invite(t, tm.owner, tm.id, guest.id)
	if code := accept(t, guest.pairClient, inv); code != http.StatusNoContent {
		t.Fatalf("accept=%d", code)
	}
	if code := accept(t, guest.pairClient, inv); code != http.StatusNotFound {
		t.Fatalf("second accept=%d", code)
	}
	again, _ := invite(t, tm.owner, tm.id, tm.viewer.id)
	if code := accept(t, tm.viewer.pairClient, again); code != http.StatusNoContent {
		t.Fatalf("re-invited former member=%d", code)
	}
}

// Invitation envelopes reach key_envelopes on acceptance, so inserting them
// needs the same password step-up as a direct envelope write.
func TestInvitationEnvelopesRequireUserStepUp(t *testing.T) {
	tm := newTeam(t)
	invitee := tm.owner.addUser(t, "invitee")
	inviteeID := invitee.createIdentity(t)
	withEnvelope := []byte(`{"inviteeId":` + quote(invitee.id) + `,"role":"editor","envelopes":[{"containerId":` + quote(tm.id) + `,` + envJSON(inviteeID, 1, 1)[1:] + `]}`)
	persisted := func() int {
		var n int
		if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM invitations)+(SELECT COUNT(*) FROM invitation_envelopes)`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	clear := func() {
		if _, err := tm.owner.db.Exec(`UPDATE sessions SET stepup_at=''`); err != nil {
			t.Error(err)
		}
	}
	clear()
	if code, body := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", withEnvelope, true, false)); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("envelope invitation without step-up: %d %s", code, body)
	}
	if n := persisted(); n != 0 {
		t.Fatalf("refused invitation persisted %d rows", n)
	}
	tm.owner.stepUp(t)
	hdr := map[string]string{"Content-Type": "application/json"}
	if code, body := tm.owner.sendRacing(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", hdr, withEnvelope, clear); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
		t.Fatalf("envelope invitation after step-up was cleared: %d %s", code, body)
	}
	if n := persisted(); n != 0 {
		t.Fatalf("stale step-up persisted %d rows", n)
	}
	// Without envelopes an invitation installs no key material: session suffices.
	if _, code := invite(t, tm.owner, tm.id, invitee.id); code != http.StatusOK {
		t.Fatalf("plain invitation without step-up=%d", code)
	}
}
