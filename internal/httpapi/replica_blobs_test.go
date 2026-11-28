package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestObjectClaimNeverProbesTheNetworkInsideWriterTransaction(t *testing.T) {
	// No database or object client exists: these paths must not attempt either operation.
	b := &requestObjects{}
	dropUnclaimed(nil, b, "digest")
	if _, ok, err := b.Stat("digest"); err == nil || ok {
		t.Fatal("unverified object admitted")
	}
	a, releaseA := requestBlobs(httptest.NewRequest("GET", "/", nil), &replicaBlobs{})
	defer releaseA()
	z, releaseZ := requestBlobs(httptest.NewRequest("GET", "/", nil), &replicaBlobs{})
	defer releaseZ()
	if a == z {
		t.Fatal("request state shared")
	}
}

func TestReplicaObjectRoutesUploadAndSaveOutsideWriterLock(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("set KYNOTES_TEST_DATABASE_URL")
	}
	u := newUploadClient(t)
	writer := replicaDB(t, u.db)
	u.db.SetMaxOpenConns(1)
	toMultiMode(t, u.db, "org_staff")
	// Existing fixture's content org is a customer; the local allowance admits its writes.
	if _, err := u.db.Exec(`INSERT INTO org_pool(org_id,ceiling_bytes,expires_at,seq) VALUES(?,100000000,'2099-01-01T00:00:00Z',1)`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	objects := map[string][]byte{}
	var networkCalls atomic.Int32
	var pauseFinalize atomic.Bool
	finalizeEntered, continueFinalize := make(chan struct{}), make(chan struct{})
	releaseFinalize := sync.OnceFunc(func() { close(continueFinalize) })
	s3server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		networkCalls.Add(1)
		// A network operation must allow another writer to start and commit, even when a
		// digest/upload session lock is held by the request driving this provider call.
		tx, err := writer.BeginTx(r.Context(), nil)
		if err != nil {
			t.Errorf("object I/O held N3: %v", err)
			w.WriteHeader(500)
			return
		}
		if err := tx.Commit(); err != nil {
			t.Error(err)
		}
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		if r.Method == "PUT" && strings.Contains(key, "/blobs/") && pauseFinalize.CompareAndSwap(true, false) {
			close(finalizeEntered)
			select {
			case <-continueFinalize:
			case <-r.Context().Done():
				return
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Query().Get("list-type") != "" || r.URL.Query().Has("versions") {
			type entry struct {
				Size    int64
				Key     string
				Version string `xml:"VersionId"`
				Latest  bool   `xml:"IsLatest"`
			}
			entries := []entry{}
			for k := range objects {
				if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
					entries = append(entries, entry{int64(len(objects[k])), k, "null", true})
				}
			}
			if r.URL.Query().Has("versions") {
				xml.NewEncoder(w).Encode(struct {
					Truncated bool     `xml:"IsTruncated"`
					XMLName   xml.Name `xml:"ListVersionsResult"`
					Entries   []entry  `xml:"Version"`
				}{Entries: entries})
			} else {
				xml.NewEncoder(w).Encode(struct {
					Truncated bool     `xml:"IsTruncated"`
					XMLName   xml.Name `xml:"ListBucketResult"`
					Entries   []entry  `xml:"Contents"`
				}{Entries: entries})
			}
			return
		}
		switch r.Method {
		case "PUT":
			objects[key], _ = io.ReadAll(r.Body)
			w.Header().Set("ETag", `"object"`)
		case "HEAD", "GET":
			raw, ok := objects[key]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
			if r.Method == "GET" {
				w.Write(raw)
			}
		case "DELETE":
			delete(objects, key)
			w.WriteHeader(204)
		default:
			w.WriteHeader(400)
		}
	}))
	defer s3server.Close()
	client, err := shareds3.New(shareds3.Config{Endpoint: s3server.URL, Bucket: "bucket", AccessKey: "test", SecretKey: "test", HTTP: s3server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	stores := storage.ObjectStores(func(_ context.Context, org string) (*blobstore.Objects, error) {
		return blobstore.NewObjects(client, "local", org, scratch, 1000)
	})
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Limits.ChunkBytes = 4
	cfg.Limits.AttachmentMaxBytes = 100
	cfg.DataDir = scratch
	server := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, u.db, cfg, stores))
	defer server.Close()
	standbyDB := replicaDB(t, u.db)
	standbyDB.SetMaxOpenConns(1)
	standby := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, standbyDB, cfg, stores))
	defer standby.Close()
	defer releaseFinalize()
	// Cookies are host scoped, so alternating ports preserves the authenticated browser.
	u.url = server.URL
	id := u.upload(t, 8, []byte("abcdefgh"))
	for turn, chunk := range []struct {
		index int
		body  string
	}{{0, "abcd"}, {0, "abcd"}, {1, "efgh"}} {
		if turn%2 == 0 {
			u.url = server.URL
		} else {
			u.url = standby.URL
		}
		res := u.chunk(t, id, chunk.index, chunk.body)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("chunk %d: %d %s", chunk.index, res.StatusCode, body)
		}
	}
	// Hold the first PUT until the second replica has read pending state and is
	// waiting on the upload lock. Both finalizers must return the same result.
	var standbyPID int
	if err := standbyDB.QueryRow(`SELECT pg_backend_pid()`).Scan(&standbyPID); err != nil {
		t.Fatal(err)
	}
	pauseFinalize.Store(true)
	replies := make(chan *http.Response, 2)
	finalizeBody := []byte(fmt.Sprintf(`{"metadataCiphertext":"","keyGeneration":%d}`, u.generation))
	go func() { replies <- u.do(t, "POST", "/api/v1/uploads/"+id+"/finalize", finalizeBody, true) }()
	select {
	case <-finalizeEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("first finalizer never reached PUT")
	}
	otherClient := *u
	otherClient.url = standby.URL
	go func() { replies <- otherClient.do(t, "POST", "/api/v1/uploads/"+id+"/finalize", finalizeBody, true) }()
	waiting := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := writer.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=? AND wait_event='advisory')`, standbyPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("second finalizer never waited on upload ownership")
	}
	releaseFinalize()
	res := <-replies
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("finalize: %d %s", res.StatusCode, raw)
	}
	var att struct {
		ID string `json:"attachmentId"`
	}
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatal(err)
	}
	second := <-replies
	secondRaw, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != 200 || !bytes.Equal(raw, secondRaw) {
		t.Fatalf("concurrent finalize: %d %s; first: %s", second.StatusCode, secondRaw, raw)
	}
	res = u.do(t, "GET", "/api/v1/attachments/"+att.ID, nil, false)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.Equal(raw, []byte("abcdefgh")) {
		t.Fatalf("download: %d %s", res.StatusCode, raw)
	}
	sum := sha256.Sum256(raw)
	key, _ := blobstore.BlobKey("local", storage.DefaultOrgID, hex.EncodeToString(sum[:]))
	mu.Lock()
	_, stored := objects[key]
	for name := range objects {
		if strings.Contains(name, "/uploads/") {
			t.Errorf("finalized parts retained: %s", name)
		}
	}
	mu.Unlock()
	if !stored || networkCalls.Load() == 0 {
		t.Fatal("object adapter not exercised")
	}
	res = u.do(t, "POST", "/api/v1/containers/"+u.container+"/objects", []byte(`{"kind":"note"}`), true)
	var object struct {
		ID string `json:"id"`
	}
	if res.StatusCode != 200 {
		t.Fatalf("create page: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&object); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	put, _ := http.NewRequest("PUT", u.url+"/api/v1/objects/"+object.ID, strings.NewReader("page-ciphertext"))
	put.Header.Set("X-Kynotes-Key-Generation", fmt.Sprint(u.generation))
	put.Header.Set("X-Kynotes-Base-Version", "0")
	put.Header.Set(keySchemeHeader, keySchemeShared)
	for _, cookie := range u.hc.Jar.Cookies(put.URL) {
		if cookie.Name == "csrf_token" {
			put.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	res, err = u.hc.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("page save: %d %s", res.StatusCode, answer)
	}
	res = u.do(t, "GET", "/api/v1/objects/"+object.ID, nil, false)
	answer, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(answer) != "page-ciphertext" {
		t.Fatalf("page read: %d %s", res.StatusCode, answer)
	}
	res = u.do(t, "POST", "/api/v1/objects/"+object.ID+"/share-links", []byte(`{"expiresAt":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`), true)
	var share struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&share); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || share.Token == "" {
		t.Fatalf("share create: %d", res.StatusCode)
	}
	public := &http.Client{}
	res, err = public.Get(server.URL + "/api/v1/share-links/" + share.Token)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(answer) != "page-ciphertext" {
		t.Fatalf("public object binding: %d %s", res.StatusCode, answer)
	}
	// A refused digest must update status on the already pinned upload connection.
	bad := u.upload(t, 4, []byte("good"))
	res = u.chunk(t, bad, 0, "oops")
	res.Body.Close()
	res = u.do(t, "POST", "/api/v1/uploads/"+bad+"/finalize", []byte(fmt.Sprintf(`{"metadataCiphertext":"","keyGeneration":%d}`, u.generation)), true)
	res.Body.Close()
	if res.StatusCode != 422 {
		t.Fatalf("refused digest: %d", res.StatusCode)
	}
	var failed string
	if err := u.db.QueryRow(`SELECT status FROM upload_sessions WHERE id=?`, bad).Scan(&failed); err != nil || failed != "failed" {
		t.Fatalf("refused upload status: %s %v", failed, err)
	}
	// Cancelling an upload with SetMaxOpenConns(1) must reuse the pinned upload lease
	// for the status update, keep remote deletion outside a write transaction, and
	// release the connection so subsequent DB queries complete within a deadline.
	cancelled := u.upload(t, 8, []byte("abcdefgh"))
	res = u.chunk(t, cancelled, 0, "abcd")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("cancel setup chunk: %d", res.StatusCode)
	}
	cancelCtx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()
	delReq, err := http.NewRequestWithContext(cancelCtx, "DELETE", u.url+"/api/v1/uploads/"+cancelled, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range u.hc.Jar.Cookies(delReq.URL) {
		if cookie.Name == "csrf_token" {
			delReq.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	res, err = u.hc.Do(delReq)
	if err != nil {
		t.Fatalf("cancel upload deadlocked or failed: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel upload: %d", res.StatusCode)
	}
	var cancelledStatus string
	if err := u.db.QueryRowContext(cancelCtx, `SELECT status FROM upload_sessions WHERE id=?`, cancelled).Scan(&cancelledStatus); err != nil || cancelledStatus != "failed" {
		t.Fatalf("cancelled upload status: %s %v", cancelledStatus, err)
	}
	mu.Lock()
	for name := range objects {
		if strings.Contains(name, "/uploads/"+cancelled+"/") {
			t.Errorf("cancelled upload part retained: %s", name)
		}
	}
	mu.Unlock()
	// A preview lookup after PUT must also share the pinned connection.
	previewSum := sha256.Sum256([]byte("tiny"))
	res = u.do(t, "POST", "/api/v1/containers/"+u.container+"/uploads", []byte(fmt.Sprintf(`{"declaredBytes":4,"expectedDigest":"%x","kind":"preview"}`, previewSum)), true)
	var preview struct {
		ID string `json:"uploadId"`
	}
	if res.StatusCode != 200 {
		t.Fatalf("preview create: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	res = u.chunk(t, preview.ID, 0, "tiny")
	res.Body.Close()
	res = u.do(t, "POST", "/api/v1/uploads/"+preview.ID+"/finalize", nil, true)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("preview finalize: %d", res.StatusCode)
	}
	withPreview := u.upload(t, 4, []byte("file"))
	res = u.chunk(t, withPreview, 0, "file")
	res.Body.Close()
	res = u.do(t, "POST", "/api/v1/uploads/"+withPreview+"/finalize", []byte(fmt.Sprintf(`{"metadataCiphertext":"","keyGeneration":%d,"previewUploadId":"%s"}`, u.generation, preview.ID)), true)
	if res.StatusCode != 200 {
		t.Fatalf("attachment with preview: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&att); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	res = u.do(t, "GET", "/api/v1/attachments/"+att.ID+"/preview", nil, false)
	previewBytes, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(previewBytes) != "tiny" {
		t.Fatalf("preview read: %d %s", res.StatusCode, previewBytes)
	}
	partial := u.upload(t, 8, []byte("abcdefgh"))
	res = u.chunk(t, partial, 0, "abcd")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("partial chunk: %d", res.StatusCode)
	}
	if _, err := u.db.Exec(`UPDATE upload_sessions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?`, partial); err != nil {
		t.Fatal(err)
	}
	if err := storage.RunObjectMaintenance(context.Background(), u.db, stores, time.Now()); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := u.db.QueryRow(`SELECT status FROM upload_sessions WHERE id=?`, partial).Scan(&status); err != nil || status != "expired" {
		t.Fatalf("expired parts remain admitted: %s %v", status, err)
	}
	// Creating a same-digest object in another org must address a different permanent key.
	other, err := stores(t.Context(), "org_other")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Put(context.Background(), hex.EncodeToString(sum[:]), bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(objects) != 5 {
		t.Fatalf("org keys collided: %d objects", len(objects))
	}
}

func TestReplicaObjectSaveRefusesSuspendedCustomerOrgWhileStaffActive(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("set KYNOTES_TEST_DATABASE_URL")
	}
	u := newUploadClient(t)
	toMultiMode(t, u.db, "org_staff")
	if _, err := u.db.Exec(`INSERT INTO org_pool(org_id,ceiling_bytes,expires_at,seq) VALUES(?,100000000,'2099-01-01T00:00:00Z',1)`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	var puts atomic.Int32
	s3server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			puts.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("ETag", `"object"`)
			return
		}
		w.WriteHeader(204)
	}))
	defer s3server.Close()
	client, err := shareds3.New(shareds3.Config{Endpoint: s3server.URL, Bucket: "bucket", AccessKey: "test", SecretKey: "test", HTTP: s3server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	stores := storage.ObjectStores(func(_ context.Context, org string) (*blobstore.Objects, error) {
		return blobstore.NewObjects(client, "local", org, scratch, 1000)
	})
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.DataDir = scratch
	server := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, u.db, cfg, stores))
	defer server.Close()
	u.url = server.URL

	res := u.do(t, "POST", "/api/v1/containers/"+u.container+"/objects", []byte(`{"kind":"note"}`), true)
	var object struct {
		ID string `json:"id"`
	}
	if res.StatusCode != 200 {
		t.Fatalf("create page: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&object); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	// Stream the body via a pipe so the handler authenticates and binds requestObjects
	// to the active customer org before suspension, then suspend the customer org
	// while the staff org remains active and finish streaming to trigger Finalize.
	pr, pw := io.Pipe()
	req, err := http.NewRequest("PUT", u.url+"/api/v1/objects/"+object.ID, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Kynotes-Key-Generation", fmt.Sprint(u.generation))
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set(keySchemeHeader, keySchemeShared)
	for _, cookie := range u.hc.Jar.Cookies(req.URL) {
		if cookie.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	done := make(chan *http.Response, 1)
	errs := make(chan error, 1)
	go func() {
		resp, err := u.hc.Do(req)
		if err != nil {
			errs <- err
			return
		}
		done <- resp
	}()
	// Writing the first chunk blocks until the handler has called NewTemp (binding b.org)
	// and started io.Copy into the temporary file.
	if _, err := pw.Write([]byte("page-")); err != nil {
		t.Fatal(err)
	}
	if _, err := u.db.Exec(`UPDATE orgs SET status='suspended' WHERE id=?`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	var staffServes int
	if err := u.db.QueryRow(`SELECT count(*) FROM orgs o WHERE o.id='org_staff' AND ` + storage.OrgServes("o.id")).Scan(&staffServes); err != nil || staffServes != 1 {
		t.Fatalf("staff org should remain active: %d %v", staffServes, err)
	}
	if _, err := pw.Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		t.Fatal(err)
	case resp := <-done:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatalf("suspended customer org save succeeded: %d %s", resp.StatusCode, body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("suspended customer org save timed out")
	}
	if got := puts.Load(); got != 0 {
		t.Fatalf("suspended customer org produced %d object PUT(s), want 0", got)
	}
	var currentVersion, versionCount int
	if err := u.db.QueryRow(`SELECT current_version FROM objects WHERE id=?`, object.ID).Scan(&currentVersion); err != nil || currentVersion != 0 {
		t.Fatalf("suspended customer org bumped current_version=%d err=%v", currentVersion, err)
	}
	if err := u.db.QueryRow(`SELECT count(*) FROM object_versions WHERE object_id=?`, object.ID).Scan(&versionCount); err != nil || versionCount != 0 {
		t.Fatalf("suspended customer org created %d object_versions err=%v", versionCount, err)
	}

	// Claim transactions must also recheck serving status if suspension races after PUT.
	digest := strings.Repeat("ab", 32)
	tx, err := u.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	lease, _, err := storage.SessionLock(context.Background(), u.db, storage.BlobLockName(storage.DefaultOrgID, digest), true)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	b := &requestObjects{org: storage.DefaultOrgID, blob: lease, digest: digest, size: 15}
	if err := claimBlob(tx, b, digest, u.container, 15, time.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("claimBlob admitted write for suspended customer org while staff org active")
	}
}
