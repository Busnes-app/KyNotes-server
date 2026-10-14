package httpapi

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestSaveReusingAMarkedBlobClearsTheMark(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE blobs SET unreferenced_since='2000-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if _, code = tm.owner.save(t, tm.id, oid, 2); code != http.StatusOK {
		t.Fatalf("resave=%d", code)
	}
	var marked int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM blobs WHERE unreferenced_since!=''`).Scan(&marked); err != nil || marked != 0 {
		t.Fatalf("reused blob still marked for GC: %d %v", marked, err)
	}
}

func TestClaimBlobRefusesAFileGCDeleted(t *testing.T) {
	root := t.TempDir()
	s, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, _ := blobstore.New(root)
	db := s.DB()
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_a','workbook','usr_a','now','now')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// The save's Finalize saw the file; GC then removed it before the save's transaction.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := claimBlob(tx, b, strings.Repeat("ab", 32), "cnt_a", 1, "now"); err == nil {
		t.Fatal("claimBlob accepted a blob with no file")
	}
}

func TestDeletingANoteTombstonesOnlyItsOwnAttachments(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	gone, _ := tm.owner.save(t, tm.id, "", 2)
	kept, _ := tm.owner.save(t, tm.id, "", 2)
	att := map[string]string{}
	for i, name := range []string{"own", "shared", "pending", "late"} {
		att[name] = mint(t, "att")
		digest := strings.Repeat(strconv.Itoa(i), 64)
		if _, err := tm.owner.db.Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,1,'now')`, digest); err != nil {
			t.Fatal(err)
		}
		if _, err := tm.owner.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,1,x'00',2,1,'now')`, att[name], tm.id, digest); err != nil {
			t.Fatal(err)
		}
	}
	link := func(oid, name string) int {
		t.Helper()
		code, _ := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/attachments", []byte(`{"attachmentId":`+quote(att[name])+`,"objectVersion":1}`), true, false))
		return code
	}
	for _, l := range [][2]string{{gone, "own"}, {gone, "shared"}, {kept, "shared"}} {
		if code := link(l[0], l[1]); code != http.StatusNoContent {
			t.Fatalf("link %s=%d", l[1], code)
		}
	}
	// "pending" was just uploaded by someone else and is not linked yet.
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/objects/"+gone, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("delete=%d %s", code, out)
	}
	for name, want := range map[string]bool{"own": true, "shared": false, "pending": false, "late": false} {
		var deletedAt string
		if err := tm.owner.db.QueryRow(`SELECT deleted_at FROM attachments WHERE id=?`, att[name]).Scan(&deletedAt); err != nil || (deletedAt != "") != want {
			t.Fatalf("%s deleted_at=%q err=%v, want deleted=%v", name, deletedAt, err, want)
		}
	}
	if code := link(kept, "own"); code != http.StatusNotFound {
		t.Fatalf("linking a deleted attachment=%d", code)
	}
	if code := link(gone, "late"); code != http.StatusNotFound {
		t.Fatalf("linking to a deleted note=%d", code)
	}
	var refs int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM attachment_refs`).Scan(&refs); err != nil || refs != 1 {
		t.Fatalf("refs=%d %v, want only kept->shared", refs, err)
	}
}

func TestReuploadRevivesADeletedAttachment(t *testing.T) {
	u := newUploadClient(t)
	upload := func() string {
		t.Helper()
		id := u.upload(t, 4, []byte("abcd"))
		u.chunk(t, id, 0, "abcd").Body.Close()
		code, out := status(t, u.do(t, http.MethodPost, "/api/v1/uploads/"+id+"/finalize", []byte(`{"metadataCiphertext":"","keyGeneration":`+strconv.FormatInt(u.generation, 10)+`}`), true))
		if code != http.StatusOK {
			t.Fatalf("finalize=%d %s", code, out)
		}
		return out
	}
	first := upload()
	if _, err := u.db.Exec(`UPDATE attachments SET deleted_at='then'`); err != nil {
		t.Fatal(err)
	}
	if again := upload(); again != first {
		t.Fatalf("re-upload=%s, want %s", again, first)
	}
	var deletedAt string
	if err := u.db.QueryRow(`SELECT deleted_at FROM attachments`).Scan(&deletedAt); err != nil || deletedAt != "" {
		t.Fatalf("deleted_at=%q %v", deletedAt, err)
	}
}

func TestUnlinkReportsAFailedWrite(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, _ := tm.owner.save(t, tm.id, "", 2)
	att := mint(t, "att")
	if _, err := tm.owner.db.Exec(`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at) SELECT ?,?,blob_digest,1,x'00',2,1,'now' FROM object_versions WHERE object_id=?`, att, tm.id, oid); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) VALUES(?,?,1,'now')`, att, oid); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`CREATE TRIGGER refs_stuck BEFORE DELETE ON attachment_refs BEGIN SELECT RAISE(ABORT,'stuck'); END`); err != nil {
		t.Fatal(err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/objects/"+oid+"/attachments/"+att, nil, true, false)); code != http.StatusInternalServerError {
		t.Fatalf("unlink=%d %s, want 500", code, out)
	}
}
