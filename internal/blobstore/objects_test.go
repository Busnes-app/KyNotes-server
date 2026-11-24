package blobstore_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
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
	"github.com/Busnes-app/kynotes-server/internal/ids"
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
	landed           chan struct{} // closed once the first blocked PUT is stored
	once             sync.Once
	gzipKey          string
	getEncoding      string
	modified         map[string]time.Time // provider age; absent is unknown
}

func newObjectFixture(t *testing.T) (*objectFixture, *shareds3.Client) {
	t.Helper()
	f := &objectFixture{objects: map[string][]byte{}, puts: map[string]int{}, failures: map[string]int{}, modified: map[string]time.Time{}}
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
	if r.URL.Path == "/bucket" {
		key = ""
	}
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
			Modified  string `xml:"LastModified,omitempty"`
		}
		age := func(k string) string {
			if at, ok := f.modified[k]; ok {
				return at.UTC().Format(time.RFC3339)
			}
			return ""
		}
		entries := []entry{}
		next := ""
		if r.URL.Query().Has("versions") {
			for _, k := range keys {
				entries = append(entries, entry{k, int64(len(f.objects[k])), "null", true, age(k)})
			}
		} else {
			token := r.URL.Query().Get("continuation-token")
			for _, k := range keys {
				if token == "" || k > token {
					entries = append(entries, entry{Key: k, Size: int64(len(f.objects[k])), Modified: age(k)})
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
		first := false
		if f.started != nil {
			f.once.Do(func() { close(f.started); first = true })
			<-f.release
		}
		f.mu.Lock()
		f.objects[key] = body
		f.mu.Unlock()
		if first && f.landed != nil {
			close(f.landed)
		}
		w.Header().Set("X-Amz-Version-Id", "null")
		w.WriteHeader(200)
		return
	}
	f.mu.Lock()
	encoded := key == f.gzipKey
	if r.Method == http.MethodGet {
		f.getEncoding = r.Header.Get("Accept-Encoding")
	}
	body, ok := f.objects[key]
	body = bytes.Clone(body)
	if r.Method == http.MethodDelete {
		delete(f.objects, key)
	}
	modified, aged := f.modified[key]
	f.mu.Unlock()
	if r.Method == http.MethodDelete {
		w.WriteHeader(204)
		return
	}
	if !ok {
		w.WriteHeader(404)
		return
	}
	if encoded {
		w.Header().Set("Content-Encoding", "gzip")
	}
	if aged {
		w.Header().Set("Last-Modified", modified.UTC().Format(http.TimeFormat))
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
	if got := fmt.Sprintf("%#v", a); got != "blobstore.Objects" {
		t.Fatal("object adapter formatting is not redacted")
	}
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

func TestObjectPartsCrossReplicasRetriesRollbackAndFinalize(t *testing.T) {
	fixture, client := newObjectFixture(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	a, b := objectStore(t, client, "org_a", dirA), objectStore(t, client, "org_a", dirB)
	other := objectStore(t, client, "org_b", t.TempDir())
	id, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	neighbor, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	chunks := [][]byte{[]byte("abcd"), []byte("efgh"), []byte("i")}
	for index, chunk := range chunks {
		store := a
		if index%2 != 0 {
			store = b
		}
		if err := store.PutPart(t.Context(), id, int64(index), bytes.NewReader(chunk), int64(len(chunk))); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.PutPart(t.Context(), id, 1, bytes.NewReader(chunks[1]), 4); err != nil {
		t.Fatal("identical chunk retry", err)
	}
	key, _ := blobstore.UploadPartKey("org_a", id, 1)
	fixture.mu.Lock()
	puts := fixture.puts[key]
	fixture.mu.Unlock()
	if puts != 1 {
		t.Fatal("retry wrote another physical version", puts)
	}
	if err := b.PutPart(t.Context(), id, 1, strings.NewReader("EFGH"), 4); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("different retry replaced a committed part", err)
	}
	if _, _, err := other.OpenPart(t.Context(), id, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("part read crossed org", err)
	}
	// The DB counter retained only chunk0: explicitly discard uncommitted remote tail.
	if err := b.DeletePartsFrom(t.Context(), id, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.OpenPart(t.Context(), id, 1); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncommitted tail retained", err)
	}
	if err := a.PutPart(t.Context(), id, 1, strings.NewReader("EFGH"), 4); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPart(t.Context(), id, 2, strings.NewReader("i"), 1); err != nil {
		t.Fatal(err)
	}
	want := []byte("abcdEFGHi")
	digest := objectDigest(want)
	stream, gotDigest, err := b.AssembleParts(t.Context(), id, 9, 4, digest)
	if err != nil || gotDigest != digest {
		t.Fatal("ordered bounded assembly", gotDigest, err)
	}
	if err := b.Put(t.Context(), digest, stream, 9); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	// Permanent PUT does not remove live parts before the caller's DB commit.
	live, _, err := a.OpenPart(t.Context(), id, 0)
	if err != nil {
		t.Fatal("parts removed before explicit commit cleanup", err)
	}
	_ = live.Close()
	if err := a.PutPart(t.Context(), neighbor, 0, strings.NewReader("neighbor"), 8); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteParts(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.OpenPart(t.Context(), id, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("parts remained after cleanup", err)
	}
	kept, _, err := a.OpenPart(t.Context(), neighbor, 0)
	if err != nil {
		t.Fatal("cleanup crossed upload id", err)
	}
	_ = kept.Close()
	permanent, _, err := a.Open(t.Context(), digest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(permanent)
	_ = permanent.Close()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("final ciphertext changed", err)
	}
	noObjectFiles(t, dirA)
	noObjectFiles(t, dirB)
}

func TestObjectPartsRefuseGapsSizesDigestAndMalformedTailWithoutLeakingFiles(t *testing.T) {
	fixture, client := newObjectFixture(t)
	dir := t.TempDir()
	store := objectStore(t, client, "org_a", dir)
	id, err := ids.Mint("ups")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutPart(t.Context(), id, 0, strings.NewReader("abcd"), 4); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AssembleParts(t.Context(), id, 8, 4, ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing chunk admitted", err)
	}
	noObjectFiles(t, dir)
	if err := store.PutPart(t.Context(), id, 1, strings.NewReader("efgh"), 4); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AssembleParts(t.Context(), id, 7, 4, ""); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("part size mismatch admitted", err)
	}
	noObjectFiles(t, dir)
	if _, _, err := store.AssembleParts(t.Context(), id, 8, 4, strings.Repeat("0", 64)); !errors.Is(err, blobstore.ErrDigestMismatch) {
		t.Fatal("wrong final digest admitted", err)
	}
	noObjectFiles(t, dir)
	key, _ := blobstore.UploadPartKey("org_a", id, 0)
	fixture.mu.Lock()
	fixture.objects[strings.TrimSuffix(key, "0")+"not-an-index"] = []byte("bad")
	fixture.mu.Unlock()
	if err := store.DeletePartsFrom(t.Context(), id, 0); !errors.Is(err, blobstore.ErrCorruptBlob) {
		t.Fatal("malformed tail admitted", err)
	}
	remaining, _, err := store.OpenPart(t.Context(), id, 0)
	if err != nil {
		t.Fatal("malformed tail allowed partial removal", err)
	}
	_ = remaining.Close()
	noObjectFiles(t, dir)
}

func TestObjectsKeepOpaqueGzipBytesAndMetadata(t *testing.T) {
	fixture, client := newObjectFixture(t)
	dir := t.TempDir()
	store := objectStore(t, client, "org_a", dir)
	var encoded bytes.Buffer
	compressor := gzip.NewWriter(&encoded)
	if _, err := compressor.Write([]byte("opaque ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	wire := encoded.Bytes()
	digest := objectDigest(wire)
	if err := store.Put(t.Context(), digest, bytes.NewReader(wire), int64(len(wire))); err != nil {
		t.Fatal(err)
	}
	key, _ := blobstore.BlobKey("org_a", digest)
	fixture.mu.Lock()
	fixture.gzipKey = key
	fixture.mu.Unlock()
	head, exists, err := store.Stat(t.Context(), digest)
	if err != nil || !exists || head != int64(len(wire)) {
		t.Fatal("HEAD did not retain wire size", head, err)
	}
	reader, size, err := store.Open(t.Context(), digest)
	if err != nil {
		t.Fatal("GET changed encoded object bytes/metadata", err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || size != head || !bytes.Equal(got, wire) {
		t.Fatal("opaque wire bytes changed", readErr, closeErr)
	}
	fixture.mu.Lock()
	accept := fixture.getEncoding
	fixture.mu.Unlock()
	if accept != "identity" {
		t.Fatalf("GET encoding=%q", accept)
	}
	noObjectFiles(t, dir)
}
