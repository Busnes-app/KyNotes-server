package blobstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// runtimeDatabase is a multi-mode PostgreSQL install serving org_a and org_b in region eu,
// each with one user, notebook and page.
func runtimeDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db := identityDatabase(t)
	for _, q := range []string{
		`INSERT INTO server_settings(key,value,updated_at) VALUES('region','eu','t'),('cell:eu','','t'),('cell:us-east-2','','t'),('staff_org_id','org_staff','t')`,
		`INSERT INTO orgs(id,status,home_region) VALUES('org_a','active','eu'),('org_b','active','us-east-2')`,
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
	if err := runtimeStore(t, client, org, t.TempDir()).Put(t.Context(), digest, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO blobs(org_id,digest,size_bytes,created_at,unreferenced_since) VALUES(?,?,?,'t',?)`, org, digest, len(body), now.Add(-2*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return digest
}

// stores is the runtime's factory: each org's objects are under its home_region's cell.
func stores(t *testing.T, db *sql.DB, client *shareds3.Client) storage.ObjectStores {
	dir := t.TempDir()
	return storage.CellObjectStores(db, func(cell, org string) (*blobstore.Objects, error) {
		return blobstore.NewObjects(client, cell, org, dir, 64)
	})
}

func objectExists(t *testing.T, client *shareds3.Client, org, digest string) bool {
	t.Helper()
	_, ok, err := runtimeStore(t, client, org, t.TempDir()).Stat(t.Context(), digest)
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
	n, err := storage.RunObjectGC(t.Context(), db, stores(t, db, client), now, time.Hour)
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
		n, err := storage.RunObjectGC(t.Context(), db, stores(t, db, client), now, time.Hour)
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
	if _, err := storage.RunObjectGC(t.Context(), db, stores(t, db, client), now, time.Hour); err == nil {
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
	if n, err := storage.RunObjectGC(t.Context(), db, stores(t, db, client), now, time.Hour); err != nil || n != 0 {
		t.Fatalf("a suspended org's blob was swept: %d %v", n, err)
	}
	if !blobRow(t, db, "org_a", d) || !objectExists(t, client, "org_a", d) {
		t.Fatal("suspended org's blob lost")
	}
	if _, err := db.Exec(`UPDATE server_settings SET value='single' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.RunObjectGC(t.Context(), db, stores(t, db, client), now, time.Hour); err == nil {
		t.Fatal("object GC ran in single mode")
	}
}

// A deleted org's purge erases its whole prefix in its cell (blobs and upload parts) and nothing
// of another org's in another cell, even for identical ciphertext.
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
	if err := runtimeStore(t, client, "org_b", t.TempDir()).PutPart(t.Context(), upload, 0, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	purge := purgeWith(stores(t, db, client))
	for range 2 { // the second run is past the late-PUT window
		if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE server_settings SET value='0' WHERE key='purge_fence:org_b'`); err != nil {
			t.Fatal(err)
		}
	}
	if keys := orgKeys(fixture, "org_b"); len(keys) != 0 {
		t.Errorf("%v survived the purge", keys)
	}
	// Everything left is org_a's, in its own cell.
	fixture.mu.Lock()
	for key := range fixture.objects {
		if !strings.HasPrefix(key, "cells/eu/orgs/org_a/") {
			t.Errorf("%q is outside org_a's cell prefix", key)
		}
	}
	fixture.mu.Unlock()
	if !objectExists(t, client, "org_a", d) || !blobRow(t, db, "org_a", d) {
		t.Fatal("the purge of org_b removed org_a's copy")
	}
	if purgedAt(t, db, "org_b") == "" {
		t.Fatal("org_b not marked purged")
	}
}

func purgeWith(stores storage.ObjectStores) storage.PurgeObjects {
	return func(ctx context.Context, org string) error {
		s, err := stores(ctx, org)
		if err != nil {
			return err
		}
		return s.Purge(ctx)
	}
}

// cellOf is runtimeDatabase's home_region of each org: two orgs in two served cells.
func cellOf(org string) string {
	if org == "org_b" {
		return "us-east-2"
	}
	return "eu"
}

// runtimeStore writes as the runtime does, under the org's cell.
func runtimeStore(t *testing.T, client *shareds3.Client, org, dir string) *blobstore.Objects {
	t.Helper()
	store, err := blobstore.NewObjects(client, cellOf(org), org, dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// orgKeys lists the org's keys in any cell, or under no cell at all.
func orgKeys(f *objectFixture, org string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for key := range f.objects {
		if strings.Contains("/"+key, "/orgs/"+org+"/") {
			keys = append(keys, key)
		}
	}
	return keys
}

func purgedAt(t *testing.T, db *sql.DB, org string) string {
	t.Helper()
	var at string
	if err := db.QueryRow(`SELECT purged_at FROM orgs WHERE id=?`, org).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// A PUT admitted before the org was deleted times out at the client, then the provider stores
// it after the purge deleted the prefix. The purge must not mark the org purged until a prefix
// delete after the late-PUT window has erased it.
func TestLatePutAfterPurgeIsErasedBeforeTheOrgIsMarkedPurged(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	putBlob(t, db, client, "org_b", []byte("stored before the delete"), time.Now())
	fixture.started, fixture.release, fixture.landed = make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer blobstore.SetPutDeadline(200 * time.Millisecond)()
	late := []byte("admitted before the delete, stored after the purge")
	put := make(chan error, 1)
	go func() {
		put <- runtimeStore(t, client, "org_b", t.TempDir()).Put(t.Context(), objectDigest(late), bytes.NewReader(late), int64(len(late)))
	}()
	<-fixture.started
	select {
	case err := <-put:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("want the put deadline, got", err)
		}
	case <-time.After(10 * time.Second):
		close(fixture.release)
		t.Fatal("an admitted PUT outlived its deadline")
	}
	if _, err := db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	purge := purgeWith(stores(t, db, client))
	if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
		t.Fatal(err)
	}
	if at := purgedAt(t, db, "org_b"); at != "" {
		close(fixture.release)
		t.Fatal("org marked purged inside the late-PUT window")
	}
	close(fixture.release)
	<-fixture.landed
	if keys := orgKeys(fixture, "org_b"); len(keys) != 1 {
		t.Fatalf("the late PUT should have landed: %v", keys)
	}
	if _, err := db.Exec(`UPDATE server_settings SET value='0' WHERE key='purge_fence:org_b'`); err != nil {
		t.Fatal(err)
	}
	if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
		t.Fatal(err)
	}
	if keys := orgKeys(fixture, "org_b"); len(keys) != 0 || purgedAt(t, db, "org_b") == "" {
		t.Fatalf("after the window: keys=%v purged_at=%q", keys, purgedAt(t, db, "org_b"))
	}
}

// The orphan sweep deletes an object no row claims only when the provider says it is over an
// hour old, and only for a serving org: a late PUT after GC or an erasure, or an abandoned
// upload's parts. Claimed, young, unknown-age and stopped orgs' objects stay.
func TestOrphanSweepDeletesOnlyOldUnclaimedObjects(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	old, young := time.Now().Add(-2*time.Hour), time.Now().Add(-10*time.Minute)
	put := func(org, body string, at time.Time) string {
		d := objectDigest([]byte(body))
		if err := runtimeStore(t, client, org, t.TempDir()).Put(t.Context(), d, strings.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
		key, _ := blobstore.BlobKey(cellOf(org), org, d)
		fixture.mu.Lock()
		if !at.IsZero() {
			fixture.modified[key] = at
		}
		fixture.mu.Unlock()
		return d
	}
	orphan := put("org_a", "late put after gc", old)
	recent := put("org_a", "put ten minutes ago", young)
	unknown := put("org_a", "no provider age", time.Time{})
	claimed := put("org_a", "claimed", old)
	stopped := put("org_b", "suspended org", old)
	if _, err := db.Exec(`INSERT INTO blobs(org_id,digest,size_bytes,created_at) VALUES('org_a',?,7,'t')`, claimed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE orgs SET status='suspended' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	part := func(pending bool) string {
		id, err := ids.Mint("ups")
		if err != nil {
			t.Fatal(err)
		}
		if err := runtimeStore(t, client, "org_a", t.TempDir()).PutPart(t.Context(), id, 0, strings.NewReader("chunk"), 5); err != nil {
			t.Fatal(err)
		}
		key, _ := blobstore.UploadPartKey("eu", "org_a", id, 0)
		fixture.mu.Lock()
		fixture.modified[key] = old
		fixture.mu.Unlock()
		if pending {
			if _, err := db.Exec(`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES(?,'usr_a','cnt_a',5,5,'t','t','t','org_a')`, id); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	abandoned, live := part(false), part(true)
	n, err := storage.SweepOrphanObjects(t.Context(), db, stores(t, db, client))
	if err != nil || n != 2 {
		t.Fatalf("swept=%d err=%v", n, err)
	}
	if objectExists(t, client, "org_a", orphan) {
		t.Error("an old unclaimed object survived")
	}
	for name, d := range map[string]string{"young": recent, "unknown age": unknown, "claimed": claimed} {
		if !objectExists(t, client, "org_a", d) {
			t.Errorf("the %s object was swept", name)
		}
	}
	if !objectExists(t, client, "org_b", stopped) {
		t.Error("a stopped org's object was swept")
	}
	for id, want := range map[string]bool{abandoned: false, live: true} {
		key, _ := blobstore.UploadPartKey("eu", "org_a", id, 0)
		fixture.mu.Lock()
		_, ok := fixture.objects[key]
		fixture.mu.Unlock()
		if ok != want {
			t.Errorf("upload %s part present=%v, want %v", id, ok, want)
		}
	}
}

// An org stopped while the sweep lists its prefix keeps its orphans: each deletion re-admits
// the org under the session lock, not from the earlier org query.
func TestOrphanSweepKeepsObjectsOfAnOrgStoppedDuringTheListing(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	old := time.Now().Add(-2 * time.Hour)
	body := "orphan of an org about to stop"
	d := objectDigest([]byte(body))
	store := runtimeStore(t, client, "org_a", t.TempDir())
	if err := store.Put(t.Context(), d, strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	upload, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutPart(t.Context(), upload, 0, strings.NewReader("chunk"), 5); err != nil {
		t.Fatal(err)
	}
	blobKey, _ := blobstore.BlobKey("eu", "org_a", d)
	partKey, _ := blobstore.UploadPartKey("eu", "org_a", upload, 0)
	fixture.mu.Lock()
	fixture.modified[blobKey], fixture.modified[partKey] = old, old
	fixture.onList = func() {
		if _, err := db.Exec(`UPDATE orgs SET status='suspended' WHERE id='org_a'`); err != nil {
			t.Error(err)
		}
	}
	fixture.mu.Unlock()
	if n, err := storage.SweepOrphanObjects(t.Context(), db, stores(t, db, client)); err != nil || n != 0 {
		t.Fatalf("swept=%d err=%v", n, err)
	}
	if keys := orgKeys(fixture, "org_a"); len(keys) != 2 {
		t.Fatalf("a stopped org lost objects: %v", keys)
	}
}

// Expiring an upload holds its lease's connection. The store lookup must not need a second
// one, or maintenance on a one-connection pool waits on itself until cancelled.
func TestObjectMaintenanceExpiresAnUploadOnAOneConnectionPool(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	id, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeStore(t, client, "org_a", t.TempDir()).PutPart(t.Context(), id, 0, strings.NewReader("chunk"), 5); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES(?,'usr_a','cnt_a',5,5,'t','t','2000-01-01T00:00:00Z','org_a')`, id); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := storage.RunObjectMaintenance(ctx, db, stores(t, db, client), time.Now()); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM upload_sessions WHERE id=?`, id).Scan(&status); err != nil || status != "expired" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	key, _ := blobstore.UploadPartKey("eu", "org_a", id, 0)
	fixture.mu.Lock()
	_, ok := fixture.objects[key]
	fixture.mu.Unlock()
	if ok {
		t.Error("the expired upload's part survived")
	}
}

// C4, no moves: a directory listing that moves org_b to another served cell leaves its objects
// readable where they were written, and its purge still erases every one of them.
func TestAMovedOrgsObjectsStayReadableAndPurged(t *testing.T) {
	db := runtimeDatabase(t)
	fixture, client := newObjectFixture(t)
	d := putBlob(t, db, client, "org_b", []byte("written in us-east-2"), time.Now())
	list := func(status string, rev int64) orgsync.ListFunc {
		return func(context.Context, int64) ([]suitedir.Org, int64, error) {
			return []suitedir.Org{{ID: "org_b", Status: status, Revision: rev, HomeRegion: "eu", Enabled: true}}, rev, nil
		}
	}
	if err := orgsync.New(db, list("active", 2)).Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err := stores(t, db, client)(t.Context(), "org_b")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Stat(t.Context(), d); err != nil || !ok {
		t.Errorf("the moved org's object is unreadable: ok=%v err=%v", ok, err)
	}
	if err := orgsync.New(db, list("deleted", 3)).Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	purge := purgeWith(stores(t, db, client))
	if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE server_settings SET value='0' WHERE key='purge_fence:org_b'`); err != nil { // past the late-PUT window
		t.Fatal(err)
	}
	if err := storage.PurgeDeletedOrgs(t.Context(), db, purge); err != nil {
		t.Fatal(err)
	}
	if keys := orgKeys(fixture, "org_b"); len(keys) != 0 || purgedAt(t, db, "org_b") == "" {
		t.Fatalf("after the purge: keys=%v purged_at=%q", keys, purgedAt(t, db, "org_b"))
	}
}
