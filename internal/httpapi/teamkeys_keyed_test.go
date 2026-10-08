package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// keyForTest gives cid a container key the way a first rotation leaves it, straight in the
// database, for tests whose subject is not the key rules: an identity row for each user that has
// none, one envelope each at the current generation, and shared_generation set to it.
func keyForTest(t *testing.T, db *sql.DB, cid string, users ...string) int64 {
	t.Helper()
	var generation int64
	if err := db.QueryRow(`UPDATE containers SET shared_generation=key_generation WHERE id=? RETURNING key_generation`, cid).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	for _, user := range users {
		var device string
		err := db.QueryRow(`SELECT id FROM devices WHERE user_id=? AND platform='identity' AND revoked_at=''`, user).Scan(&device)
		if errors.Is(err, sql.ErrNoRows) {
			device = mint(t, "dev")
			_, err = db.Exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES(?,?,?,?,'identity:test','identity','now')`, device, user, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "test-"+device)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,?,?,?,'now')`, mint(t, "env"), cid, device, generation, envelopeAlg, bytes.Repeat([]byte{1}, 93)); err != nil {
			t.Fatal(err)
		}
	}
	return generation
}

func TestUnkeyedContainerRefusesEveryWrite(t *testing.T) {
	tm := newTeam(t)
	// The object row holds no ciphertext until a save, so creating it is not a content write.
	res := tm.editor.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/objects", []byte(`{"kind":"note"}`), true, false)
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var object struct{ ID string }
	if res.StatusCode != http.StatusOK || json.Unmarshal(data, &object) != nil {
		t.Fatalf("create object=%d %s", res.StatusCode, data)
	}
	if _, code := tm.editor.save(t, tm.id, object.ID, 1); code != http.StatusConflict {
		t.Fatalf("save without a key=%d", code)
	}
	if _, code := tm.editor.comment(t, object.ID, 1); code != http.StatusConflict {
		t.Fatalf("comment without a key=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 1); code != http.StatusConflict {
		t.Fatalf("attachment without a key=%d", code)
	}
	if code, body := status(t, tm.editor.do(t, http.MethodPatch, "/api/v1/containers/"+tm.id, []byte(`{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":1}`), true, false)); code != http.StatusConflict || !strings.Contains(body, "key rotation incomplete") {
		t.Fatalf("name without a key=%d %s", code, body)
	}
	tm.owner.stepUp(t)
	if code, body := status(t, tm.owner.do(t, http.MethodPut, "/api/v1/containers/"+tm.id+"/envelopes", []byte(`{"envelopes":[`+envJSON(tm.editorID, 1, 1)+`]}`), true, false)); code != http.StatusConflict {
		t.Fatalf("envelope without a key=%d %s", code, body)
	}
	// The first rotation is the only way in; afterwards the same writes pass at generation 2.
	tm.rotate(t, tm.id, 1)
	if _, code := tm.editor.save(t, tm.id, object.ID, 2); code != http.StatusOK {
		t.Fatalf("save after the first key=%d", code)
	}
	if _, code := tm.editor.comment(t, object.ID, 2); code != http.StatusOK {
		t.Fatalf("comment after the first key=%d", code)
	}
	if code := tm.editor.attach(t, tm.id, 2); code != http.StatusOK {
		t.Fatalf("attachment after the first key=%d", code)
	}
}

func TestEveryWriteNeedsTheCurrentKeyScheme(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	for _, scheme := range []string{"", "shared-v1"} {
		headers := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1"}
		if scheme != "" {
			headers[keySchemeHeader] = scheme
		}
		if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, headers, "ciphertext"); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("save with scheme %q=%d %s", scheme, code, body)
		}
	}
	headers := map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": "1", keySchemeHeader: "shared-v2"}
	if code, body := tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, headers, "ciphertext"); code != http.StatusOK {
		t.Fatalf("save with shared-v2=%d %s", code, body)
	}
}

func TestContainerCreationTakesNoName(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	if code, body := status(t, p.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":"Y3Q="}`), true, false)); code != http.StatusBadRequest {
		t.Fatalf("create with a name=%d %s", code, body)
	}
	code, body := status(t, p.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false))
	if code != http.StatusOK || !strings.Contains(body, `"sharedGeneration":0`) || !strings.Contains(body, `"metaCiphertext":""`) {
		t.Fatalf("create without a name=%d %s", code, body)
	}
}

// An envelope alone does not key a container: only a rotation sets shared_generation. An old tab
// is told to reload whether or not the container has a key yet.
func TestUnkeyedContainerNeedsARotationNotAnEnvelope(t *testing.T) {
	tm := newTeam(t)
	oid, code := tm.editor.save(t, tm.id, "", 1)
	if code != http.StatusConflict {
		t.Fatalf("save without a key=%d", code)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES(?,?,?,1,?,?,'now')`, mint(t, "env"), tm.id, tm.editorID, envelopeAlg, bytes.Repeat([]byte{1}, 93)); err != nil {
		t.Fatal(err)
	}
	if _, code := tm.editor.save(t, tm.id, oid, 1); code != http.StatusConflict {
		t.Fatalf("save with an envelope but no key=%d", code)
	}
	for name, write := range map[string]func() (int, string){
		"save": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPut, "/api/v1/objects/"+oid, map[string]string{"X-Kynotes-Key-Generation": "1", "X-Kynotes-Base-Version": "0"}, "ciphertext")
		},
		"meta": func() (int, string) {
			return tm.editor.rawWrite(t, http.MethodPatch, "/api/v1/containers/"+tm.id, nil, `{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":1}`)
		},
	} {
		if code, body := write(); code != http.StatusConflict || !strings.Contains(body, "reload") {
			t.Fatalf("%s from an old tab=%d %s", name, code, body)
		}
	}
}
