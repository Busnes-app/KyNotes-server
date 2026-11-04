package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

// Q7: comment creation has its own bucket; reading comments and other routes are not in it.
func TestCommentCreationIsRateLimited(t *testing.T) {
	cfg := config.Defaults()
	cfg.RateLimit.UploadPerMinute = 1
	h := rateLimitMiddleware(cfg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "203.0.113.7:44444"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call("POST", "/api/v1/objects/obj_a/comments"); got != http.StatusOK {
		t.Fatalf("first comment=%d", got)
	}
	if got := call("POST", "/api/objects/obj_b/comments"); got != http.StatusTooManyRequests {
		t.Fatalf("second comment=%d, want 429", got)
	}
	if got := call("GET", "/api/v1/objects/obj_a/comments"); got != http.StatusOK {
		t.Fatalf("reading comments=%d, want 200", got)
	}
	if got := call("POST", "/api/v1/containers/cnt_a/uploads"); got != http.StatusOK {
		t.Fatalf("upload after comments=%d, want its own bucket", got)
	}
}

// Q7: a comment is capped at 64 KiB, charged to the notebook owner's quota, and frees its bytes
// once its page is gone.
func TestCommentsAreCappedAndCharged(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	comment := func(n int) (int, string) {
		body := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", n)))
		return status(t, tm.editor.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"`+body+`","keyGeneration":2}`), true, false))
	}
	if code, out := comment(MaxCommentBytes + 1); code != http.StatusRequestEntityTooLarge || !strings.Contains(out, "payload_too_large") {
		t.Fatalf("oversized comment=%d %s", code, out)
	}
	ownerScope := `SELECT id FROM containers WHERE owner_user_id=?1`
	before, err := usedBytes(tm.owner.db, ownerScope, pairUser, "")
	if err != nil {
		t.Fatal(err)
	}
	if code, out := comment(MaxCommentBytes); code != http.StatusOK {
		t.Fatalf("comment at the cap=%d %s", code, out)
	}
	after, err := usedBytes(tm.owner.db, ownerScope, pairUser, "")
	if err != nil || after-before != MaxCommentBytes {
		t.Fatalf("comment charged %d bytes (%v), want %d", after-before, err, MaxCommentBytes)
	}
	if _, err = tm.owner.db.Exec(`UPDATE users SET quota_bytes=? WHERE id=?`, after+10, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, out := comment(100); code != http.StatusRequestEntityTooLarge || !strings.Contains(out, "quota_exceeded") {
		t.Fatalf("comment past quota=%d %s", code, out)
	}
	var stored int
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/objects/"+oid, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("page delete=%d %s", code, out)
	}
	if err = tm.owner.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE object_id=?`, oid).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("a deleted page kept %d comments %v", stored, err)
	}
	// The page's own version bytes went too.
	before = 0
	if gone, err := usedBytes(tm.owner.db, ownerScope, pairUser, ""); err != nil || gone != before {
		t.Fatalf("deleted page's comments still charged: %d (before %d) %v", gone, before, err)
	}
	// ...and a deleted page takes no new ones, which would never be charged.
	if code, out := comment(100); code != http.StatusNotFound {
		t.Fatalf("comment on a deleted page=%d %s", code, out)
	}
}

// A deleted notebook's finalized previews no longer count against its owner.
func TestDeletedNotebookPreviewsAreNotCharged(t *testing.T) {
	u := newUploadClient(t)
	data := "abcdefgh"
	sum := sha256.Sum256([]byte(data))
	code, out := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", []byte(`{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"preview"}`), true))
	if code != http.StatusOK {
		t.Fatalf("preview start=%d %s", code, out)
	}
	var v struct {
		ID string `json:"uploadId"`
	}
	_ = json.Unmarshal([]byte(out), &v)
	u.chunk(t, v.ID, 0, data[:4]).Body.Close()
	u.chunk(t, v.ID, 1, data[4:]).Body.Close()
	if code := u.finalize(t, v.ID); code != http.StatusOK {
		t.Fatalf("finalize=%d", code)
	}
	scope := `SELECT id FROM containers WHERE owner_user_id=?1`
	if used, err := usedBytes(u.db, scope, "usr_upload_test", ""); err != nil || used != int64(len(data)) {
		t.Fatalf("preview charged %d %v", used, err)
	}
	if _, err := u.db.Exec(`UPDATE containers SET deleted_at='now' WHERE id=?`, u.container); err != nil {
		t.Fatal(err)
	}
	if used, err := usedBytes(u.db, scope, "usr_upload_test", ""); err != nil || used != 0 {
		t.Fatalf("deleted notebook's preview still charged %d %v", used, err)
	}
}
