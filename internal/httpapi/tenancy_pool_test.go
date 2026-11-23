package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// grant gives org a pool grant of ceiling bytes until expires.
func grant(t *testing.T, p *pairClient, org string, ceiling int64, expires time.Time) {
	t.Helper()
	if _, err := p.db.Exec(`INSERT INTO org_pool(org_id,ceiling_bytes,expires_at) VALUES(?,?,?) ON CONFLICT(org_id) DO UPDATE SET ceiling_bytes=excluded.ceiling_bytes,expires_at=excluded.expires_at`, org, ceiling, expires.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// orgBWriter is a member of org_b in a multi-mode install, signed in, with a keyed notebook.
func orgBWriter(t *testing.T) (p *pairClient, b member, cid string, generation int64) {
	t.Helper()
	p = newPairClient(t, strings.Repeat("p", 32))
	b = p.addUserInOrg(t, "b-writer", "org_b") // signs in by password before multi mode refuses it (N5)
	toMultiMode(t, p.db, "org_staff")
	code, body := status(t, b.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true, false))
	var c struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &c) != nil {
		t.Fatalf("org_b member's notebook: %d %s", code, body)
	}
	return p, b, c.ID, keyForTest(t, p.db, c.ID, b.id)
}

// Every org-owned row a member of a non-default org writes through the API names that org: the
// parent's org, in the insert itself (spec, Isolation).
func TestOrgMemberWritesLandInItsOrg(t *testing.T) {
	p, b, cid, generation := orgBWriter(t)
	grant(t, p, "org_b", 1<<30, time.Now().Add(time.Hour))
	oid, code := b.save(t, cid, "", generation)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	data := []byte("attachment-ciphertext")
	sum := sha256.Sum256(data)
	_, body := status(t, b.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/uploads", []byte(`{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"attachment"}`), true, false))
	var up struct{ UploadID string }
	if json.Unmarshal([]byte(body), &up) != nil || up.UploadID == "" {
		t.Fatalf("upload: %s", body)
	}
	req, _ := http.NewRequest(http.MethodPatch, b.url+"/api/v1/uploads/"+up.UploadID, bytes.NewReader(data))
	req.Header.Set("X-Kynotes-Chunk-Index", "0")
	req.Header.Set(keySchemeHeader, keySchemeShared)
	for _, c := range b.hc.Jar.Cookies(req.URL) {
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	if res, err := b.hc.Do(req); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("chunk: %v", err)
	}
	if code, body := status(t, b.do(t, http.MethodPost, "/api/v1/uploads/"+up.UploadID+"/finalize", []byte(`{"metadataCiphertext":"","keyGeneration":`+strconv.FormatInt(generation, 10)+`}`), true, false)); code != http.StatusOK {
		t.Fatalf("finalize: %d %s", code, body)
	}
	if code, body := status(t, b.do(t, http.MethodPost, "/api/v1/share-links", []byte(`{"ciphertext":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`","expiresAt":"`+time.Now().UTC().Add(time.Hour).Format(time.RFC3339)+`"}`), true, false)); code != http.StatusOK {
		t.Fatalf("sealed link: %d %s", code, body)
	}
	for table, q := range map[string]string{
		"containers":         `SELECT count(*) FROM containers WHERE id='` + cid + `' AND org_id='org_b'`,
		"object_versions":    `SELECT count(*) FROM object_versions WHERE object_id='` + oid + `' AND org_id='org_b'`,
		"blobs":              `SELECT count(*) FROM blobs WHERE org_id='org_b'`,
		"blob_containers":    `SELECT count(*) FROM blob_containers WHERE container_id='` + cid + `' AND org_id='org_b'`,
		"attachments":        `SELECT count(*) FROM attachments WHERE container_id='` + cid + `' AND org_id='org_b'`,
		"upload_sessions":    `SELECT count(*) FROM upload_sessions WHERE id='` + up.UploadID + `' AND org_id='org_b'`,
		"sealed_share_links": `SELECT count(*) FROM sealed_share_links WHERE owner_user_id='` + b.id + `' AND org_id='org_b'`,
	} {
		if n := count(t, p.db, q); n == 0 {
			t.Errorf("%s: no org_b row", table)
		}
	}
}

// The pool (owner decision 14): a write that adds bytes needs an unexpired grant with room for
// it; without one it answers 413 quota_exceeded, while deletes still pass.
func TestPoolGrantGatesGrowthOnly(t *testing.T) {
	p, b, cid, generation := orgBWriter(t)
	oid, code := b.save(t, cid, "", generation) // no grant yet
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a save with no grant: %d", code)
	}
	grant(t, p, "org_b", 1<<30, time.Now().Add(-time.Second))
	if _, code = b.save(t, cid, oid, generation); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a save on an expired grant: %d", code)
	}
	grant(t, p, "org_b", 1, time.Now().Add(time.Hour)) // less than any write below: nothing is stored yet
	if _, code = b.save(t, cid, oid, generation); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a save past the ceiling: %d", code)
	}
	if code, body := status(t, b.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":`+strconv.FormatInt(generation, 10)+`}`), true, false)); code != http.StatusRequestEntityTooLarge || errorCode(t, body) != "quota_exceeded" {
		t.Fatalf("a comment past the ceiling: %d %s", code, body)
	}
	if code, body := status(t, b.do(t, http.MethodPost, "/api/v1/share-links", []byte(`{"ciphertext":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`","expiresAt":"`+time.Now().UTC().Add(time.Hour).Format(time.RFC3339)+`"}`), true, false)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a sealed link past the ceiling: %d %s", code, body)
	}
	if code, body := status(t, b.do(t, http.MethodPost, "/api/v1/containers/"+cid+"/uploads", []byte(`{"declaredBytes":64,"kind":"attachment"}`), true, false)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an upload past the ceiling: %d %s", code, body)
	}
	if code, _ := status(t, b.do(t, http.MethodDelete, "/api/v1/objects/"+oid, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("a delete over the pool: %d", code)
	}
	grant(t, p, "org_b", 1<<30, time.Now().Add(time.Hour))
	if _, code = b.save(t, cid, "", generation); code != http.StatusOK {
		t.Fatalf("a save within the grant: %d", code)
	}
}
