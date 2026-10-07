package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rawWrite sends an authorized content write without the key-scheme header, as a
// tab loaded before team keys would.
func (p *pairClient) rawWrite(t *testing.T, method, path string, headers map[string]string, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, p.url+path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
	return status(t, res)
}

func TestSharedContainerRefusesStaleClientWrites(t *testing.T) {
	tm := newTeam(t)
	oid, _ := tm.editor.save(t, tm.id, "", 1)
	cmt, _ := tm.editor.comment(t, oid, 1)
	// Never shared: a client without the header keeps working (personal notebooks, old tabs).
	legacy := map[string]string{"X-Kynotes-Key-Generation": "1", "X-Kynotes-Base-Version": "1"}
	if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, legacy, "ciphertext"); code != http.StatusOK {
		t.Fatalf("legacy container without header=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1)
	stale := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "2"}
	for name, write := range map[string]func() (int, string){
		"save": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, stale, "ciphertext")
		},
		"comment": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", nil, `{"bodyCiphertext":"Y3Q=","keyGeneration":2}`)
		},
		"meta": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPatch, "/api/v1/containers/"+tm.id, nil, `{"metaCiphertext":"Y3Q=","baseVersion":0}`)
		},
		"comment rewrite": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPut, "/api/v1/comments/"+cmt, nil, `{"bodyCiphertext":"Y3Q=","keyGeneration":2}`)
		},
	} {
		if code, body := write(); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("%s from a stale client=%d %s", name, code, body)
		}
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id=? AND key_generation=2`, oid).Scan(&versions); err != nil || versions != 0 {
		t.Fatalf("stale write stored %d versions: %v", versions, err)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusOK {
		t.Fatalf("current client=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 2); code != http.StatusOK {
		t.Fatalf("current client upload=%d", code)
	}
}

// joinTeam adds an editor with an identity to the team after it rotated.
func (tm team) joinTeam(t *testing.T, name string) (member, string) {
	t.Helper()
	m := tm.owner.addUser(t, name)
	if _, err := tm.owner.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES(?,?,?,'editor','now')`, mint(t, "mem"), tm.id, m.id); err != nil {
		t.Fatal(err)
	}
	return m, m.createIdentity(t)
}

func TestStewardBackfillsSharedHistoryOnly(t *testing.T) {
	tm := newTeam(t)
	put := func(c *pairClient, items ...string) (int, string) {
		return status(t, c.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", envelopesBody(items...), true, false))
	}
	tm.owner.stepUp(t)
	// A legacy-era envelope at generation 1 (the device gate's kind) must not open generation 1 to backfill.
	if code, body := put(tm.owner, envJSON(tm.editorID, 1, 1)); code != http.StatusNoContent {
		t.Fatalf("legacy envelope=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1) // shared from generation 2
	tm.rotate(t, tm.id, 2)
	newcomer, newcomerID := tm.joinTeam(t, "newcomer")
	tm.owner.stepUp(t)
	for _, g := range []int64{1, 4} { // before sharing, and not yet minted
		if code, body := put(tm.owner, envJSON(newcomerID, g, 1)); code != http.StatusConflict {
			t.Fatalf("backfill at %d=%d %s", g, code, body)
		}
	}
	tm.editor.stepUp(t)
	if code, _ := put(tm.editor.pairClient, envJSON(newcomerID, 2, 1)); code != http.StatusForbidden {
		t.Fatalf("editor wrapped for a colleague=%d", code)
	}
	if code, body := put(tm.owner, envJSON(newcomerID, 2, 1), envJSON(newcomerID, 3, 1)); code != http.StatusNoContent {
		t.Fatalf("backfill=%d %s", code, body)
	}
	if code, _ := put(tm.owner, envJSON(newcomerID, 2, 2)); code != http.StatusConflict {
		t.Fatalf("second wrap at an old generation=%d", code)
	}
	if _, code := newcomer.save(t, tm.id, "", 3); code != http.StatusOK {
		t.Fatalf("newcomer save=%d", code)
	}
}

func TestSharedGenerationIsMintedOnlyByRotation(t *testing.T) {
	tm := newTeam(t)
	tm.owner.stepUp(t)
	put := func(cid string, items ...string) (int, string) {
		return status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+cid+"/envelopes", envelopesBody(items...), true, false))
	}
	// Legacy containers keep today's rule: the first envelope at the current generation is a PUT.
	if code, body := put(tm.child, envJSON(tm.editorID, 1, 1)); code != http.StatusNoContent {
		t.Fatalf("legacy first envelope=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1)
	if code, body := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id+"/members/"+tm.admin.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", code, body)
	}
	tm.owner.stepUp(t)
	if code, body := put(tm.id, envJSON(tm.ownerID, 3, 1), envJSON(tm.editorID, 3, 1)); code != http.StatusConflict || !strings.Contains(body, "key rotation incomplete") {
		t.Fatalf("mint by PUT after removal=%d %s", code, body)
	}
	if n := countEnvelopes(t, tm.owner, tm.id, 3); n != 0 {
		t.Fatalf("PUT minted %d envelopes", n)
	}
	body := rotationBody(3, envJSON(tm.ownerID, 4, 1), envJSON(tm.editorID, 4, 1))
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/key-rotations", body, true, false)); code != http.StatusOK {
		t.Fatalf("rotate=%d %s", code, out)
	}
}

func TestContainersReportSharedGeneration(t *testing.T) {
	tm := newTeam(t)
	shared := func() map[string]int64 {
		res := tm.editor.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)
		var list []struct {
			ID               string `json:"id"`
			SharedGeneration *int64 `json:"sharedGeneration"`
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]int64{}
		for _, c := range list {
			if c.SharedGeneration == nil {
				t.Fatalf("container %s without sharedGeneration: %s", c.ID, data)
			}
			out[c.ID] = *c.SharedGeneration
		}
		return out
	}
	if got := shared(); got[tm.id] != 0 || got[tm.child] != 0 {
		t.Fatalf("before rotation: %v", got)
	}
	tm.rotate(t, tm.id, 1)
	if got := shared(); got[tm.id] != 2 || got[tm.child] != 0 {
		t.Fatalf("after rotation: %v", got)
	}
	code, created := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false))
	if code != http.StatusOK || !strings.Contains(created, `"sharedGeneration":0`) {
		t.Fatalf("create=%d %s", code, created)
	}
}
