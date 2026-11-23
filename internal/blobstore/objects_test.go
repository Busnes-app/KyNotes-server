package blobstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Product boundary fixture only: real shared client/TLS and S3 wire replies, no client/signing
// implementation. Actual provider/signature qualification belongs to shared-client integration.
type objectFixture struct {
	mu               sync.Mutex
	objects          map[string][]byte
	puts             map[string]int
	failures         map[string]int
	started, release chan struct{}
	once             sync.Once
}

func newObjectFixture(t *testing.T) (*objectFixture, *shareds3.Client) {
	t.Helper()
	f := &objectFixture{objects: map[string][]byte{}, puts: map[string]int{}, failures: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	client, err := shareds3.New(shareds3.Config{Endpoint: server.URL, Bucket: "bucket", Region: "local", AccessKey: "object-fixture-access", SecretKey: "object-fixture-secret", HTTP: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return f, client
}
func (f *objectFixture) serve(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	f.mu.Lock()
	if r.Method == http.MethodPut {
		f.puts[key]++
	}
	failure := f.failures[r.Method]
	f.mu.Unlock()
	if failure != 0 {
		w.WriteHeader(failure)
		_, _ = io.WriteString(w, "object-fixture-secret provider body")
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(403)
		return
	}
	if r.Method == http.MethodGet && key == "" {
		f.mu.Lock()
		keys := []string{}
		for k := range f.objects {
			if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		type entry struct {
			Key       string
			Size      int64
			VersionID string `xml:"VersionId,omitempty"`
			Latest    bool   `xml:"IsLatest,omitempty"`
		}
		entries := []entry{}
		next := ""
		if r.URL.Query().Has("versions") {
			for _, k := range keys {
				entries = append(entries, entry{k, int64(len(f.objects[k])), "null", true})
			}
		} else {
			token := r.URL.Query().Get("continuation-token")
			for _, k := range keys {
				if token == "" || k > token {
					entries = append(entries, entry{Key: k, Size: int64(len(f.objects[k]))})
				}
			}
			if len(entries) > 1 {
				next = entries[0].Key
				entries = entries[:1]
			}
		}
		f.mu.Unlock()
		if r.URL.Query().Has("versions") {
			_ = xml.NewEncoder(w).Encode(struct {
				XMLName   xml.Name `xml:"ListVersionsResult"`
				Truncated bool     `xml:"IsTruncated"`
				Entries   []entry  `xml:"Version"`
			}{Entries: entries})
		} else {
			_ = xml.NewEncoder(w).Encode(struct {
				XMLName   xml.Name `xml:"ListBucketResult"`
				Truncated bool     `xml:"IsTruncated"`
				Next      string   `xml:"NextContinuationToken,omitempty"`
				Entries   []entry  `xml:"Contents"`
			}{Truncated: next != "", Next: next, Entries: entries})
		}
		return
	}
	if r.Method == http.MethodPut {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if f.started != nil {
			f.once.Do(func() { close(f.started) })
			<-f.release
		}
		f.mu.Lock()
		f.objects[key] = body
		f.mu.Unlock()
		w.Header().Set("X-Amz-Version-Id", "null")
		w.WriteHeader(200)
		return
	}
	f.mu.Lock()
	body, ok := f.objects[key]
	body = bytes.Clone(body)
	if r.Method == http.MethodDelete {
		delete(f.objects, key)
	}
	f.mu.Unlock()
	if r.Method == http.MethodDelete {
		w.WriteHeader(204)
		return
	}
	if !ok {
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Amz-Version-Id", "null")
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
func objectDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func noObjectFiles(t *testing.T, dir string) {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("private files leaked: %d %v", len(files), err)
	}
}
func objectStore(t *testing.T, client *shareds3.Client, org, dir string) *blobstore.Objects {
	t.Helper()
	store, err := blobstore.NewObjects(client, org, dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestObjectsVerifyPrivateStreamsDeduplicateAndKeepOrgsSeparate(t *testing.T) {
	fixture, client := newObjectFixture(t)
	dir := t.TempDir()
	a := objectStore(t, client, "org_a", dir)
	b := objectStore(t, client, "org_b", dir)
	body := []byte("opaque ciphertext")
	digest := objectDigest(body)
	for _, store := range []*blobstore.Objects{a, a, b} {
		if err := store.Put(t.Context(), digest, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
	}
	keyA, _ := blobstore.BlobKey("org_a", digest)
	keyB, _ := blobstore.BlobKey("org_b", digest)
	fixture.mu.Lock()
	putsA, putsB := fixture.puts[keyA], fixture.puts[keyB]
	fixture.mu.Unlock()
	if putsA != 1 || putsB != 1 {
		t.Fatalf("duplicate/current or cross-org keys: %d/%d", putsA, putsB)
	}
	reader, size, err := a.Open(t.Context(), digest)
	if err != nil || size != int64(len(body)) {
		t.Fatal(size, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("read did not own one private file", err)
	}
	info, err := os.Stat(dir + "/" + files[0].Name())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("read file is not private", err)
	}
	if _, err := reader.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, body[7:]) {
		t.Fatal("seekable stream changed", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	noObjectFiles(t, dir)
	digests, err := a.ListDigests(t.Context())
	if err != nil || len(digests) != 1 || digests[0] != digest {
		t.Fatal(digests, err)
	}
	if err := a.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := a.Stat(t.Context(), digest); err != nil || exists {
		t.Fatal("org purge retained a key", err)
	}
	if _, exists, err := b.Stat(t.Context(), digest); err != nil || !exists {
		t.Fatal("purge crossed org", err)
	}
	if err := b.Delete(t.Context(), digest); err != nil {
		t.Fatal(err)
	}
}

func TestObjectsRefuseCorruptionOversizeCancellationAndStorageFailures(t *testing.T) {
	fixture, client := newObjectFixture(t)
	dir := t.TempDir()
	store := objectStore(t, client, "org_a", dir)
	body := []byte("opaque ciphertext")
	digest := objectDigest(body)
	key, _ := blobstore.BlobKey("org_a", digest)
	for _, test := range []struct {
		digest string
		body   []byte
		size   int64
	}{{digest, []byte("wrong bytes"), int64(len(body))}, {digest, body, int64(len(body) - 1)}, {digest, bytes.Repeat([]byte("x"), 65), 65}, {"../digest", body, int64(len(body))}} {
		if err := store.Put(t.Context(), test.digest, bytes.NewReader(test.body), test.size); err == nil {
			t.Fatal("invalid bytes admitted")
		}
		noObjectFiles(t, dir)
	}
	fixture.mu.Lock()
	putKeys := len(fixture.puts)
	fixture.mu.Unlock()
	if putKeys != 0 {
		t.Fatal("invalid bytes reached PUT")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Put(ctx, digest, bytes.NewReader(body), int64(len(body))); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	noObjectFiles(t, dir)
	if err := store.Put(t.Context(), digest, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.objects[key] = bytes.Repeat([]byte("x"), len(body))
	fixture.mu.Unlock()
	if _, _, err := store.Open(t.Context(), digest); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("corrupt ciphertext exposed", err)
	}
	if err := store.Put(t.Context(), digest, bytes.NewReader(body), int64(len(body))); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("corrupt existing key overwritten", err)
	}
	noObjectFiles(t, dir)
	fixture.mu.Lock()
	fixture.failures[http.MethodHead] = 403
	fixture.mu.Unlock()
	if _, _, err := store.Stat(t.Context(), digest); err == nil || strings.Contains(err.Error(), "object-fixture-secret") {
		t.Fatal("storage failure hidden or secret disclosed", err)
	}
	fixture.mu.Lock()
	delete(fixture.failures, http.MethodHead)
	fixture.objects[key] = bytes.Repeat([]byte("x"), 65)
	fixture.mu.Unlock()
	if _, _, err := store.Open(t.Context(), digest); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("oversized object admitted", err)
	}
	noObjectFiles(t, dir)
	if _, err := blobstore.NewObjects(client, "../org", dir, 64); err == nil {
		t.Fatal("org traversal accepted")
	}
}

func TestObjectsListPaginationAndCanonicalKeys(t *testing.T) {
	fixture, client := newObjectFixture(t)
	store := objectStore(t, client, "org_a", t.TempDir())
	for _, body := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		if err := store.Put(t.Context(), objectDigest(body), bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.ListDigests(t.Context()); err != nil || len(got) != 3 {
		t.Fatal("pagination lost objects", got, err)
	}
	fixture.mu.Lock()
	fixture.objects["orgs/org_a/blobs/not/canonical"] = []byte("bad")
	fixture.mu.Unlock()
	if _, err := store.ListDigests(t.Context()); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("malformed object key admitted", err)
	}
}

func TestObjectsPutAcrossSingleConnectionPoolsHoldsOnlyTheKeyLock(t *testing.T) {
	db := identityDatabase(t)
	var schema string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	pool := func() *storage.Store {
		p, err := storage.OpenPostgresCurrent(t.Context(), dsn.String())
		if err != nil {
			t.Fatal(err)
		}
		p.DB().SetMaxOpenConns(1)
		t.Cleanup(func() { p.Close() })
		return p
	}
	a, b := pool(), pool()
	fixture, client := newObjectFixture(t)
	fixture.started = make(chan struct{})
	fixture.release = make(chan struct{})
	body := []byte("concurrent ciphertext")
	digest := objectDigest(body)
	store := objectStore(t, client, storage.DefaultOrgID, t.TempDir())
	results := make(chan error, 2)
	for _, p := range []*storage.Store{a, b} {
		go func(db *sql.DB) {
			lease, _, err := storage.SessionLock(t.Context(), db, "blob/"+storage.DefaultOrgID+"/"+digest, true)
			if err != nil {
				results <- err
				return
			}
			defer lease.Release()
			if err := store.Put(lease.Context, digest, bytes.NewReader(body), int64(len(body))); err != nil {
				results <- err
				return
			}
			tx, err := lease.Begin()
			if err != nil {
				results <- err
				return
			}
			defer tx.Rollback()
			if _, err := tx.Exec(`INSERT INTO blobs(org_id,digest,size_bytes,created_at) VALUES(?,?,?,'t') ON CONFLICT(org_id,digest) DO NOTHING`, storage.DefaultOrgID, digest, len(body)); err != nil {
				results <- err
				return
			}
			results <- tx.Commit()
		}(p.DB())
	}
	select {
	case <-fixture.started:
	case err := <-results:
		close(fixture.release)
		t.Fatal("PUT failed before reaching provider", err)
	case <-time.After(10 * time.Second):
		close(fixture.release)
		t.Fatal("PUT did not reach provider")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	tx, probeErr := db.BeginTx(ctx, nil)
	if probeErr == nil {
		_, probeErr = tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('objects_io_probe','ok','t')`)
		_ = tx.Rollback()
	}
	cancel()
	close(fixture.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if probeErr != nil {
		t.Fatal("object I/O held N3", probeErr)
	}
	key, _ := blobstore.BlobKey(storage.DefaultOrgID, digest)
	fixture.mu.Lock()
	puts := fixture.puts[key]
	fixture.mu.Unlock()
	if puts != 1 {
		t.Fatalf("duplicate PUTs=%d", puts)
	}
	var claims int
	if err := db.QueryRow(`SELECT count(*) FROM blobs WHERE org_id=? AND digest=?`, storage.DefaultOrgID, digest).Scan(&claims); err != nil || claims != 1 {
		t.Fatal("claim mismatch", claims, err)
	}
}
