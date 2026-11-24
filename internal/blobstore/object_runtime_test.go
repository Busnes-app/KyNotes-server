package blobstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// runtimeDatabase is a multi-mode PostgreSQL install serving org_a and org_b in region eu,
// each with one user, notebook and page.
func runtimeDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db := identityDatabase(t)
	for _, q := range []string{
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,home_region) VALUES('org_a','active','eu'),('org_b','active','eu')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('usr_a','a','x','x',1,'t','t','org_a'),('usr_b','b','x','x',1,'t','t','org_b')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('cnt_a','workbook','usr_a','t','t','org_a'),('cnt_b','workbook','usr_b','t','t','org_b')`,
		`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_a','cnt_a','note',1,'t','t'),('obj_b','cnt_b','note',1,'t','t')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%.60s: %v", q, err)
		}
	}
	return db
}

// putBlob stores body for org as an unreferenced blob marked two hours ago.
func putBlob(t *testing.T, db *sql.DB, client *shareds3.Client, org string, body []byte, now time.Time) string {
	t.Helper()
	digest := objectDigest(body)
	if err := objectStore(t, client, org, t.TempDir()).Put(t.Context(), digest, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO blobs(org_id,digest,size_bytes,created_at,unreferenced_since) VALUES(?,?,?,'t',?)`, org, digest, len(body), now.Add(-2*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return digest
}

func stores(t *testing.T, client *shareds3.Client) storage.ObjectStores {
	dir := t.TempDir()
	return func(org string) (*blobstore.Objects, error) { return blobstore.NewObjects(client, org, dir, 64) }
}

func objectExists(t *testing.T, client *shareds3.Client, org, digest string) bool {
	t.Helper()
	_, ok, err := objectStore(t, client, org, t.TempDir()).Stat(t.Context(), digest)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func blobRow(t *testing.T, db *sql.DB, org, digest string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM blobs WHERE org_id=? AND digest=?`, org, digest).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// The same ciphertext in two orgs is two objects: GC of one org's unreferenced copy keeps the
// other org's referenced copy, its row and its object.
func TestObjectGCSweepsOnlyTheUnreferencedOrgsCopy(t *testing.T) {
	db := runtimeDatabase(t)
	_, client := newObjectFixture(t)
	now := time.Now()
	body := []byte("same ciphertext")
	d := putBlob(t, db, client, "org_a", body, now)
	putBlob(t, db, client, "org_b", body, now)
	if _, err := db.Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('obj_b',1,?,1,1,1,'t','org_b')`, d); err != nil {
		t.Fatal(err)
	}
	n, err := storage.RunObjectGC(t.Context(), db, stores(t, client), now, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("deleted=%d err=%v", n, err)
	}
	if blobRow(t, db, "org_a", d) || objectExists(t, client, "org_a", d) {
		t.Fatal("org_a's unreferenced blob survived")
	}
	if !blobRow(t, db, "org_b", d) || !objectExists(t, client, "org_b", d) {
		t.Fatal("org_b's referenced blob was swept with org_a's")
	}
	var mark string
	if err := db.QueryRow(`SELECT unreferenced_since FROM blobs WHERE org_id='org_b' AND digest=?`, d).Scan(&mark); err != nil || mark != "" {
		t.Fatalf("referenced blob kept its mark %q %v", mark, err)
	}
}

// A save holding the blob's session lock commits its claim before GC's re-check, so GC keeps it.
func TestObjectGCWaitsForTheBlobLockAndRechecks(t *testing.T) {
	db := runtimeDatabase(t)
	_, client := newObjectFixture(t)
	now := time.Now()
	d := putBlob(t, db, client, "org_a", []byte("claimed during gc"), now)
	lease, _, err := storage.SessionLock(t.Context(), db, storage.BlobLockName("org_a", d), true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		n, err := storage.RunObjectGC(t.Context(), db, stores(t, client), now, time.Hour)
		if err == nil && n != 0 {
			err = context.Canceled
		}
		done <- err
	}()
	select {
	case err := <-done:
		lease.Release()
		t.Fatal("GC ran without the blob lock", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := lease.Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('obj_a',1,?,1,1,1,'t','org_a')`, d); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err := <-done; err != nil {
		t.Fatal("GC swept a claimed blob or failed:", err)
	}
	if !blobRow(t, db, "org_a", d) || !objectExists(t, client, "org_a", d) {
		t.Fatal("claimed blob lost")
	}
}

// Rows commit before the object delete; a failed delete leaves an object with no row (storage
// only), never a row with no object.
func TestObjectGCDeleteFailureLeavesNoRowPointingAtAMissingObject(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	now := time.Now()
	d := putBlob(t, db, client, "org_a", []byte("delete fails"), now)
	fixture.mu.Lock()
	fixture.failures["DELETE"] = 503
	fixture.mu.Unlock()
	if _, err := storage.RunObjectGC(t.Context(), db, stores(t, client), now, time.Hour); err == nil {
		t.Fatal("a failed object delete reported success")
	}
	fixture.mu.Lock()
	delete(fixture.failures, "DELETE")
	fixture.mu.Unlock()
	if blobRow(t, db, "org_a", d) || !objectExists(t, client, "org_a", d) {
		t.Fatal("want the row gone and the object left")
	}
}

func TestObjectGCWaitsWhileTheOrgIsStoppedAndRefusesSingleMode(t *testing.T) {
	db := runtimeDatabase(t)
	_, client := newObjectFixture(t)
	now := time.Now()
	d := putBlob(t, db, client, "org_a", []byte("suspended"), now)
	if _, err := db.Exec(`UPDATE orgs SET status='suspended' WHERE id='org_a'`); err != nil {
		t.Fatal(err)
	}
	if n, err := storage.RunObjectGC(t.Context(), db, stores(t, client), now, time.Hour); err != nil || n != 0 {
		t.Fatalf("a suspended org's blob was swept: %d %v", n, err)
	}
	if !blobRow(t, db, "org_a", d) || !objectExists(t, client, "org_a", d) {
		t.Fatal("suspended org's blob lost")
	}
	if _, err := db.Exec(`UPDATE server_settings SET value='single' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.RunObjectGC(t.Context(), db, stores(t, client), now, time.Hour); err == nil {
		t.Fatal("object GC ran in single mode")
	}
}

// A deleted org's purge erases its whole prefix (blobs and upload parts) and nothing of another
// org's, even for identical ciphertext.
func TestPurgeDeletesOnlyTheDeletedOrgsPrefix(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	now := time.Now()
	body := []byte("purged ciphertext")
	d := putBlob(t, db, client, "org_b", body, now)
	putBlob(t, db, client, "org_a", body, now)
	upload, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	if err := objectStore(t, client, "org_b", t.TempDir()).PutPart(t.Context(), upload, 0, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	resolve := stores(t, client)
	purge := func(ctx context.Context, org string) error {
		s, err := resolve(org)
		if err != nil {
			return err
		}
		return s.Purge(ctx)
	}
	if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	for key := range fixture.objects {
		if bytes.HasPrefix([]byte(key), []byte("orgs/org_b/")) {
			t.Errorf("%s survived the purge", key)
		}
	}
	fixture.mu.Unlock()
	if !objectExists(t, client, "org_a", d) || !blobRow(t, db, "org_a", d) {
		t.Fatal("the purge of org_b removed org_a's copy")
	}
	var purgedAt string
	if err := db.QueryRow(`SELECT purged_at FROM orgs WHERE id='org_b'`).Scan(&purgedAt); err != nil || purgedAt == "" {
		t.Fatalf("purged_at=%q %v", purgedAt, err)
	}
}
