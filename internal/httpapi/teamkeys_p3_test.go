package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	stale := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1"}
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
	} {
		if code, body := write(); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("%s from a stale client=%d %s", name, code, body)
		}
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id=?`, oid).Scan(&versions); err != nil || versions != 1 {
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

func TestSharedNameNeedsCurrentGeneration(t *testing.T) {
	tm := newTeam(t)
	rename := func(body string) (int, string) {
		return status(t, tm.editor.do(t, http.MethodPatch, "/api/v1/containers/"+tm.id, []byte(body), true, false))
	}
	// Without a key there is no name to seal.
	if code, body := rename(`{"metaCiphertext":"Y3Q=","baseVersion":0}`); code != http.StatusConflict {
		t.Fatalf("unkeyed rename=%d %s", code, body)
	}
	tm.rotate(t, tm.id, 1) // shared at generation 2
	for name, body := range map[string]string{
		"no generation":  `{"metaCiphertext":"Y3Q=","baseVersion":0}`,
		"retired":        `{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":1}`,
		"not yet minted": `{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":3}`,
	} {
		if code, out := rename(body); code != http.StatusConflict || !strings.Contains(out, "already_exists") {
			t.Fatalf("%s=%d %s", name, code, out)
		}
	}
	var version int64
	if err := tm.owner.db.QueryRow(`SELECT meta_version FROM containers WHERE id=?`, tm.id).Scan(&version); err != nil || version != 0 {
		t.Fatalf("stale rename stored: version=%d %v", version, err)
	}
	if code, body := rename(`{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":2}`); code != http.StatusOK {
		t.Fatalf("current rename=%d %s", code, body)
	}
}

func TestConflictListingReportsKeyGeneration(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.editor.save(t, tm.id, "", 2)
	if _, code := tm.editor.save(t, tm.id, oid, 2); code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	stale := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1", keySchemeHeader: keySchemeShared}
	if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, stale, "rejected"); code != http.StatusConflict {
		t.Fatalf("stale base=%d %s", code, body)
	}
	res := tm.editor.do(t, http.MethodGet, "/api/v1/objects/"+oid+"/conflicts", nil, false, false)
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var list []struct {
		KeyGeneration *int64 `json:"keyGeneration"`
	}
	if err := json.Unmarshal(data, &list); err != nil || len(list) != 1 || list[0].KeyGeneration == nil || *list[0].KeyGeneration != 2 {
		t.Fatalf("conflicts=%s %v", data, err)
	}
}

func TestConcurrentRenamesFromOneBaseOneWins(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1) // shared at generation 2
	path := "/api/v1/containers/" + tm.id
	for round := int64(0); round < 5; round++ {
		codes := make([]int, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, c := range []*pairClient{tm.owner, tm.editor.pairClient} {
			wg.Add(1)
			go func(i int, c *pairClient) {
				defer wg.Done()
				codes[i], errs[i] = c.send(http.MethodPatch, path, []byte(fmt.Sprintf(`{"metaCiphertext":"Y3Q=","baseVersion":%d,"keyGeneration":2}`, round)))
			}(i, c)
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatal(errs)
		}
		if codes[0]+codes[1] != http.StatusOK+http.StatusConflict {
			t.Fatalf("round %d codes=%v, want one 200 and one 409", round, codes)
		}
		var version int64
		if err := tm.owner.db.QueryRow(`SELECT meta_version FROM containers WHERE id=?`, tm.id).Scan(&version); err != nil || version != round+1 {
			t.Fatalf("round %d meta_version=%d %v", round, version, err)
		}
	}
}

// A rename, rotation or removal committed after the PATCH arrived must refuse it.
func TestMetaPatchRechecksInsideTheTransaction(t *testing.T) {
	for name, tc := range map[string]struct {
		commit string
		code   int
		want   string
	}{
		"rename":   {`UPDATE containers SET meta_version=meta_version+1 WHERE id=?1`, http.StatusConflict, "version_conflict"},
		"rotation": {`UPDATE containers SET key_generation=key_generation+1 WHERE id=?1`, http.StatusConflict, "key rotation incomplete"},
		"removal":  {`UPDATE memberships SET revoked_at='now' WHERE container_id=?1 AND user_id=?2`, http.StatusNotFound, "not_found"},
		"demotion": {`UPDATE memberships SET role='viewer' WHERE container_id=?1 AND user_id=?2`, http.StatusForbidden, "forbidden"},
	} {
		t.Run(name, func(t *testing.T) {
			tm := newTeam(t)
			tm.rotate(t, tm.id, 1) // shared at generation 2
			commit := func() {
				if _, err := tm.owner.db.Exec(tc.commit, tm.id, tm.editor.id); err != nil {
					t.Error(err)
				}
			}
			hdr := map[string]string{"Content-Type": "application/json", keySchemeHeader: keySchemeShared}
			code, body := tm.editor.sendRacing(t, http.MethodPatch, "/api/v1/containers/"+tm.id, hdr, []byte(`{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":2}`), commit)
			if code != tc.code || !strings.Contains(body, tc.want) {
				t.Fatalf("PATCH after %s=%d %s", name, code, body)
			}
			var meta []byte
			if err := tm.owner.db.QueryRow(`SELECT meta_ciphertext FROM containers WHERE id=?`, tm.id).Scan(&meta); err != nil || string(meta) == "ct" {
				t.Fatalf("refused PATCH stored its name: %q %v", meta, err)
			}
		})
	}
}
