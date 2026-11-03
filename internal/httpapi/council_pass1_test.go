package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// blobFiles counts the content-addressed files beside the test database.
func blobFiles(t *testing.T, p *pairClient) int {
	t.Helper()
	var seq int
	var name, file string
	if err := p.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	n := 0
	_ = filepath.WalkDir(filepath.Join(filepath.Dir(file), "blobs"), func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// A save refused for quota never leaves a blob file outside quota and GC.
func TestRefusedSaveLeavesNoBlobFile(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	before := blobFiles(t, tm.owner)
	if _, err := tm.owner.db.Exec(`UPDATE users SET quota_bytes=15 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	// Each refused body differs, so each would have been a new file.
	for i := 0; i < 3; i++ {
		var base int64
		_ = tm.owner.db.QueryRow(`SELECT current_version FROM objects WHERE id=?`, oid).Scan(&base)
		code, _ := tm.owner.sendRacing(t, http.MethodPut, "/api/v1/objects/"+oid, map[string]string{"X-Kynotes-Key-Generation": "2", "X-Kynotes-Base-Version": strconv.FormatInt(base, 10), keySchemeHeader: keySchemeShared}, []byte("refused-"+strconv.Itoa(i)), func() {})
		if code != http.StatusRequestEntityTooLarge {
			t.Fatalf("save over quota=%d", code)
		}
	}
	if after := blobFiles(t, tm.owner); after != before {
		t.Fatalf("refused saves left %d blob files", after-before)
	}
}

// Deleting a page elsewhere makes a later save of it fail, never a hidden success.
func TestSaveToADeletedPageIsRefused(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodDelete, "/api/v1/objects/"+oid, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("delete=%d %s", code, out)
	}
	if _, code := tm.owner.save(t, tm.id, oid, 2); code != http.StatusNotFound {
		t.Fatalf("save to deleted page=%d, want 404", code)
	}
	// Deleted while the body streamed.
	other, _ := tm.owner.save(t, tm.id, "", 2)
	del := func() {
		if _, err := tm.owner.db.Exec(`UPDATE objects SET deleted_at='now' WHERE id=?`, other); err != nil {
			t.Error(err)
		}
	}
	if code := tm.owner.saveRacing(t, other, 2, del); code != http.StatusNotFound {
		t.Fatalf("save racing a delete=%d, want 404", code)
	}
	var versions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE object_id IN (?,?)`, oid, other).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("versions=%d %v, want only other's first save", versions, err)
	}
}

// Disabling an account ends its sessions, so re-enabling it revives none.
func TestDisablingAnAccountEndsItsSessions(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	admin := tm.owner.addAdmin(t, "ops")
	admin.stepUp(t)
	patch := func(state string) {
		t.Helper()
		if code, out := status(t, admin.do(t, http.MethodPatch, "/api/v1/admin/users/"+tm.editor.id, []byte(`{"role":"user","status":"`+state+`","quotaBytes":0}`), true, false)); code != http.StatusNoContent {
			t.Fatalf("%s=%d %s", state, code, out)
		}
	}
	patch("disabled")
	patch("active")
	if code, out := status(t, tm.editor.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/objects", []byte(`{"kind":"note"}`), true, false)); code != http.StatusUnauthorized {
		t.Fatalf("old session after re-enable=%d %s, want 401", code, out)
	}
	var live int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=? AND platform<>'identity' AND revoked_at=''`, tm.editor.id).Scan(&live); err != nil || live != 0 {
		t.Fatalf("live paired devices=%d %v", live, err)
	}
}

// Finalized previews stay charged while their blob is kept.
func TestFinalizedPreviewsCountTowardQuota(t *testing.T) {
	u := newUploadClient(t, func(c *config.Config) { c.Limits.UserQuotaBytes = 10 })
	preview := func(data string) (string, int) {
		t.Helper()
		sum := sha256.Sum256([]byte(data))
		code, out := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", []byte(`{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"preview"}`), true))
		if code != http.StatusOK {
			return "", code
		}
		var v struct {
			ID string `json:"uploadId"`
		}
		_ = json.Unmarshal([]byte(out), &v)
		u.chunk(t, v.ID, 0, data[:4]).Body.Close()
		u.chunk(t, v.ID, 1, data[4:]).Body.Close()
		return v.ID, u.finalize(t, v.ID)
	}
	first, code := preview("abcdefgh")
	if code != http.StatusOK {
		t.Fatalf("first preview=%d", code)
	}
	// Cancelling a finalized preview keeps its blob, so it stays charged.
	if code, out := status(t, u.do(t, http.MethodDelete, "/api/v1/uploads/"+first, nil, true)); code != http.StatusNoContent {
		t.Fatalf("cancel=%d %s", code, out)
	}
	if _, code := preview("ijklmnop"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("second preview past quota=%d, want 413", code)
	}
}

// The same preview bytes stored once are charged once.
func TestDuplicatePreviewsAreChargedOnce(t *testing.T) {
	u := newUploadClient(t, func(c *config.Config) { c.Limits.UserQuotaBytes = 20 })
	sum := sha256.Sum256([]byte("abcdefgh"))
	for i := 0; i < 2; i++ {
		code, out := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", []byte(`{"declaredBytes":8,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"preview"}`), true))
		if code != http.StatusOK {
			t.Fatalf("preview %d start=%d %s", i, code, out)
		}
		var v struct {
			ID string `json:"uploadId"`
		}
		_ = json.Unmarshal([]byte(out), &v)
		u.chunk(t, v.ID, 0, "abcd").Body.Close()
		u.chunk(t, v.ID, 1, "efgh").Body.Close()
		if code := u.finalize(t, v.ID); code != http.StatusOK {
			t.Fatalf("preview %d finalize=%d", i, code)
		}
	}
	// 8 bytes stored: 12 more fit in a 20-byte quota.
	if code, out := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", []byte(`{"declaredBytes":12,"kind":"attachment"}`), true)); code != http.StatusOK {
		t.Fatalf("upload after duplicate previews=%d %s", code, out)
	}
}

// A chunk whose counter update was lost is written once when it is sent again.
func TestChunkRetryAfterALostCounterIsWrittenOnce(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, []byte("abcdefgh"))
	u.chunk(t, id, 0, "abcd").Body.Close()
	if _, err := u.db.Exec(`UPDATE upload_sessions SET received_bytes=0,next_chunk=0 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	for i, c := range []string{"abcd", "efgh"} {
		if res := u.chunk(t, id, i, c); res.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d=%d", i, res.StatusCode)
		} else {
			res.Body.Close()
		}
	}
	if code := u.finalize(t, id); code != http.StatusOK {
		t.Fatalf("finalize=%d", code)
	}
}

// A finalize or link retried after a lost response answers as the first one did.
func TestFinalizeAndLinkRetriesAreIdempotent(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 4, []byte("abcd"))
	u.chunk(t, id, 0, "abcd").Body.Close()
	body := []byte(`{"metadataCiphertext":"","keyGeneration":` + strconv.FormatInt(u.generation, 10) + `}`)
	var first, again struct {
		ID string `json:"attachmentId"`
	}
	for _, out := range []*struct {
		ID string `json:"attachmentId"`
	}{&first, &again} {
		code, text := status(t, u.do(t, http.MethodPost, "/api/v1/uploads/"+id+"/finalize", body, true))
		if code != http.StatusOK || json.Unmarshal([]byte(text), out) != nil {
			t.Fatalf("finalize=%d %s", code, text)
		}
	}
	if first.ID == "" || again.ID != first.ID {
		t.Fatalf("retry attachment %q, first %q", again.ID, first.ID)
	}
	code, text := status(t, u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/objects", []byte(`{"kind":"note"}`), true))
	var obj struct{ ID string }
	if code != http.StatusOK || json.Unmarshal([]byte(text), &obj) != nil {
		t.Fatalf("object=%d %s", code, text)
	}
	for i := 0; i < 2; i++ {
		if code, out := status(t, u.do(t, http.MethodPost, "/api/v1/objects/"+obj.ID+"/attachments", []byte(`{"attachmentId":"`+first.ID+`","objectVersion":0}`), true)); code != http.StatusNoContent {
			t.Fatalf("link %d=%d %s", i, code, out)
		}
	}
}

// A save refused inside its transaction drops its file unless a blobs row claims the digest.
func TestDropUnclaimedKeepsOnlyClaimedFiles(t *testing.T) {
	root := t.TempDir()
	s, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, _ := blobstore.New(root)
	write := func(body string) string {
		t.Helper()
		tmp, err := b.NewTemp(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tmp.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		d, _, err := tmp.Finalize("")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	orphan, claimed := write("orphan"), write("claimed")
	if _, err := s.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,7,'now')`, claimed); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	dropUnclaimed(tx, b, orphan)
	dropUnclaimed(tx, b, claimed)
	_ = tx.Rollback()
	if _, ok, _ := b.Stat(orphan); ok {
		t.Fatal("unclaimed file kept")
	}
	if _, ok, _ := b.Stat(claimed); !ok {
		t.Fatal("claimed file dropped")
	}
}
