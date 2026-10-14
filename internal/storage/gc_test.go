package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

func TestGCDeletesEnvelopesOfExpiredInvitations(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now'),('usr_b','b','h','s',100000,'now','now')`)
	exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_t','team','usr_a','now','now')`)
	exec(`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('dev_b','usr_b','pk','fp','x','identity','now')`)
	for id, expires := range map[string]string{"inv_old": stamp(-time.Minute), "inv_live": stamp(time.Hour)} {
		exec(`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES(?,'cnt_t','usr_a','usr_b',?,'editor','now',?)`, id, "hash-"+id, expires)
		exec(`INSERT INTO invitation_envelopes(invitation_id,container_id,device_id,key_generation,alg,envelope) VALUES(?,'cnt_t','dev_b',1,'x25519-hkdf-sha256-chacha20poly1305',x'01')`, id)
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := db.Query(`SELECT invitation_id FROM invitation_envelopes`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left = append(left, id)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "inv_live" {
		t.Fatalf("envelopes left=%v, want only inv_live", left)
	}
	var invitations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM invitations`).Scan(&invitations); err != nil || invitations != 2 {
		t.Fatalf("GC deleted invitation rows: %d %v", invitations, err)
	}
}

func TestGCDeletesExpiredLinkRequests(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.DB()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_a','usr_a','t','c','now','` + stamp(time.Hour) + `','` + stamp(time.Hour) + `')`,
		`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES('lnk_old','usr_a','ses_a',zeroblob(32),'now','` + stamp(-time.Minute) + `'),('lnk_live','usr_a','ses_a',zeroblob(32),'now','` + stamp(time.Minute) + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunGC(db, nil, now, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left string
	if err := db.QueryRow(`SELECT group_concat(id) FROM link_requests`).Scan(&left); err != nil || left != "lnk_live" {
		t.Fatalf("left=%q %v, want lnk_live", left, err)
	}
}

// blobFixture opens a store with one note and returns a helper that writes a blob file
// and its row, marked unreferenced two hours before now.
func blobFixture(t *testing.T, now time.Time) (*sql.DB, *blobstore.Store, func(content string) string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b, err := blobstore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	db := s.DB()
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_a','a','h','s',100000,'now','now')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_a','workbook','usr_a','now','now')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_a','cnt_a','note',1,'now','now')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db, b, func(content string) string {
		t.Helper()
		tmp, err := b.NewTemp(content)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tmp.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		d, size, err := tmp.Finalize("")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO blobs(digest,size_bytes,created_at,unreferenced_since) VALUES(?,?,'now',?)`, d, size, now.Add(-2*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO blob_containers(digest,container_id,first_seen_at) VALUES(?,'cnt_a','now')`, d); err != nil {
			t.Fatal(err)
		}
		return d
	}
}

func blobState(t *testing.T, db *sql.DB, b *blobstore.Store, d string) (row, file bool) {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM blobs WHERE digest=?`, d).Scan(&n); err != nil {
		t.Fatal(err)
	}
	_, file, err := b.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	return n == 1, file
}

func TestGCSweepKeepsABlobReferencedAfterSelection(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	db, b, blob := blobFixture(t, now)
	d := blob("reused")
	// GC selected d as a candidate; a save then committed a version that reuses it.
	if _, err := db.Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES('obj_a',1,?,6,1,1,'now')`, d); err != nil {
		t.Fatal(err)
	}
	deleted, err := sweepBlob(db, b, d, now.Add(-time.Hour).Format(time.RFC3339))
	if err != nil || deleted {
		t.Fatalf("sweep deleted=%v err=%v", deleted, err)
	}
	if row, file := blobState(t, db, b, d); !row || !file {
		t.Fatalf("referenced blob lost: row=%v file=%v", row, file)
	}
}

func TestGCDeletesUnreferencedBlobAndItsExpiredTombstones(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	db, b, blob := blobFixture(t, now)
	d := blob("orphan")
	for _, q := range []string{
		`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at,deleted_at) VALUES('att_gone','cnt_a',?,6,x'00',1,1,'now','then')`,
		`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,resolved_at) VALUES('cfl_done','obj_a','cnt_a',0,1,?,6,1,1,'now','then')`,
	} {
		if _, err := db.Exec(q, d); err != nil {
			t.Fatal(err)
		}
	}
	st, err := RunGC(db, b, now, time.Hour, true)
	if err != nil || st.DeletedBlobs != 1 {
		t.Fatalf("stats=%+v err=%v", st, err)
	}
	if row, file := blobState(t, db, b, d); row || file {
		t.Fatalf("swept blob left row=%v file=%v", row, file)
	}
}

func TestGCKeepsBlobsWithLiveReferencesAndClearsTheirMark(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	db, b, blob := blobFixture(t, now)
	linked, versioned := blob("linked"), blob("versioned")
	for _, q := range []string{
		`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at,deleted_at) VALUES('att_linked','cnt_a','` + linked + `',6,x'00',1,1,'now','then')`,
		`INSERT INTO attachment_refs(attachment_id,object_id,object_version,created_at) VALUES('att_linked','obj_a',1,'now')`,
		`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES('obj_a',1,'` + versioned + `',9,1,1,'now')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunGC(db, b, now, time.Hour, true); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{linked, versioned} {
		var mark string
		if err := db.QueryRow(`SELECT unreferenced_since FROM blobs WHERE digest=?`, d).Scan(&mark); err != nil || mark != "" {
			t.Fatalf("mark=%q err=%v", mark, err)
		}
		if _, file := blobState(t, db, b, d); !file {
			t.Fatal("referenced blob file deleted")
		}
	}
}
