package mirror

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/offsite"
)

func fixture(t *testing.T) (*storage.Store, *blobstore.Store, offsite.Target, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	blobs, err := blobstore.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := offsite.Config{URL: "file://" + t.TempDir()}
	target, err := offsite.Parse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return st, blobs, target, TargetKey(cfg)
}
func addBlob(t *testing.T, st *storage.Store, blobs *blobstore.Store, id string, reader io.Reader) Object {
	t.Helper()
	temp, err := blobs.NewTemp(id)
	if err != nil {
		t.Fatal(err)
	}
	defer temp.Abort()
	if _, err = io.Copy(temp, reader); err != nil {
		t.Fatal(err)
	}
	digest, size, err := temp.Finalize("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES(?,?,'')`, digest, size); err != nil {
		t.Fatal(err)
	}
	return Object{Digest: digest, Size: size}
}

type controlled struct {
	offsite.Target
	putErr, getErr error
	bad            bool
	closed         *bool
}

func (c controlled) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if c.putErr != nil {
		return c.putErr
	}
	return c.Target.Put(ctx, name, r, size)
}
func (c controlled) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	if c.bad {
		return &closingReader{Reader: strings.NewReader("corrupt"), closed: c.closed}, nil
	}
	return c.Target.Get(ctx, name)
}

type closingReader struct {
	io.Reader
	closed *bool
}

func (r *closingReader) Close() error {
	if r.closed != nil {
		*r.closed = true
	}
	return nil
}
func TestMirrorRetryIdentityAndRecovery(t *testing.T) {
	st, blobs, target, key := fixture(t)
	b := addBlob(t, st, blobs, "first", strings.NewReader("opaque test bytes"))
	ctx := context.Background()
	inventory := []Object{b}
	stats, err := Sync(ctx, st.DB(), blobs, controlled{Target: target, putErr: errors.New("offline")}, key, inventory)
	if err == nil || stats.Failed != 1 {
		t.Fatal("failed upload counted")
	}
	if pending, err := Pending(st.DB(), key); err != nil || pending != 1 {
		t.Fatal("failed upload recorded")
	}
	stats, err = Sync(ctx, st.DB(), blobs, target, key, inventory)
	if err != nil || stats.Uploaded != 1 {
		t.Fatal(stats, err)
	}
	stats, err = Sync(ctx, st.DB(), blobs, target, key, inventory)
	if err != nil || stats.Skipped != 1 {
		t.Fatal("retry did not skip")
	}
	stats, err = Sync(ctx, st.DB(), blobs, controlled{Target: target, putErr: offsite.ErrObjectExists}, "changed-target", inventory)
	if err != nil || stats.Uploaded != 1 {
		t.Fatal("existing object was not verified", err)
	}
	closed := false
	stats, err = Sync(ctx, st.DB(), blobs, controlled{Target: target, putErr: offsite.ErrObjectExists, bad: true, closed: &closed}, "corrupt-target", inventory)
	if err == nil || !closed {
		t.Fatal("corrupt existing replica accepted or reader leaked")
	}
	if err = blobs.Delete(b.Digest); err != nil {
		t.Fatal(err)
	}
	stats, err = Fetch(ctx, st.DB(), blobs, target)
	if err != nil || stats.Fetched != 1 {
		t.Fatal("fetch failed", stats, err)
	}
	f, _, err := blobs.Open(b.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = blobs.Delete(b.Digest); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{true, false} {
		failure := errors.New("unavailable")
		if missing {
			failure = os.ErrNotExist
		}
		stats, err = Fetch(ctx, st.DB(), blobs, controlled{Target: target, getErr: failure})
		if err == nil || stats.Failed != 1 || (stats.Missing == 1) != missing {
			t.Fatal("missing and unavailable conflated")
		}
	}
	closed = false
	stats, err = Fetch(ctx, st.DB(), blobs, controlled{Target: target, bad: true, closed: &closed})
	if err == nil || !closed {
		t.Fatal("corrupt download accepted or leaked")
	}
	if _, ok, err := blobs.Stat(b.Digest); err != nil || ok {
		t.Fatal("bad download finalized")
	}
	// An interrupted read must close its remote connection and remove staging bytes.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = Fetch(cancelled, st.DB(), blobs, target); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, err = st.DB().Exec(`DELETE FROM blobs WHERE digest=?`, b.Digest); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = st.DB().QueryRow(`SELECT count(*) FROM blob_replicas`).Scan(&count); err != nil || count != 0 {
		t.Fatal("GC did not cascade")
	}
	stats, err = Sync(ctx, st.DB(), blobs, target, key, inventory)
	if err == nil || stats.Missing != 1 {
		t.Fatal("snapshot blob vanished silently after GC")
	}
}
func TestTargetIdentityTracksNamespace(t *testing.T) {
	cfg := offsite.Config{URL: "sftp://alice@host/path", HostKey: "SHA256:first", Secret: "password"}
	key := TargetKey(cfg)
	cfg.Secret = "rotated"
	if TargetKey(cfg) != key {
		t.Fatal("password changed namespace")
	}
	cfg.URL = "sftp://bob@host/path"
	if TargetKey(cfg) == key {
		t.Fatal("user-relative namespace omitted")
	}
	cfg.URL = "sftp://alice@host/path"
	cfg.HostKey = "SHA256:second"
	if TargetKey(cfg) == key {
		t.Fatal("host identity omitted")
	}
	cfg = offsite.Config{URL: "s3://bucket/path", S3Endpoint: "https://one.example", AccessKey: "first", Secret: "one"}
	key = TargetKey(cfg)
	cfg.AccessKey = "rotated"
	cfg.Secret = "two"
	if TargetKey(cfg) != key {
		t.Fatal("S3 credentials changed target")
	}
	cfg.S3Endpoint = "https://two.example"
	if TargetKey(cfg) == key {
		t.Fatal("S3 endpoint omitted")
	}
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) { clear(b); return len(b), nil }
func TestStreamBlobLargerThanCapsuleMemberLimit(t *testing.T) {
	st, blobs, target, key := fixture(t)
	b := addBlob(t, st, blobs, "large", io.LimitReader(zeros{}, capsule.MaxFileBytes+1))
	if b.Size <= capsule.MaxFileBytes {
		t.Fatal("fixture too small")
	}
	if _, err := Sync(context.Background(), st.DB(), blobs, target, key, []Object{b}); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Delete(b.Digest); err != nil {
		t.Fatal(err)
	}
	stats, err := Fetch(context.Background(), st.DB(), blobs, target)
	if err != nil || stats.Fetched != 1 {
		t.Fatal(stats, err)
	}
	f, size, err := blobs.Open(b.Digest)
	if err != nil || size != b.Size {
		t.Fatal("large blob not recovered")
	}
	f.Close()
}
func TestInterruptedTransferDoesNotPublish(t *testing.T) {
	st, blobs, target, _ := fixture(t)
	b := addBlob(t, st, blobs, "interrupt", strings.NewReader("a complete ciphertext fixture"))
	if err := blobs.Delete(b.Digest); err != nil {
		t.Fatal(err)
	}
	reader := &failingReadCloser{Reader: bytes.NewReader([]byte("partial"))}
	stats, err := Fetch(context.Background(), st.DB(), blobs, readerTarget{Target: target, reader: reader})
	if err == nil || stats.Failed != 1 || !reader.closed {
		t.Fatal("interrupted transfer not cleaned up")
	}
	if _, ok, _ := blobs.Stat(b.Digest); ok {
		t.Fatal("partial download published")
	}
}

type failingReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *failingReadCloser) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	if e == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, e
}
func (r *failingReadCloser) Close() error { r.closed = true; return nil }

type readerTarget struct {
	offsite.Target
	reader io.ReadCloser
}

func (r readerTarget) Get(context.Context, string) (io.ReadCloser, error) { return r.reader, nil }

func TestFetchRepairsCorruptLocalFile(t *testing.T) {
	st, blobs, target, key := fixture(t)
	b := addBlob(t, st, blobs, "repair", strings.NewReader("correct synthetic ciphertext"))
	if _, err := Sync(context.Background(), st.DB(), blobs, target, key, []Object{b}); err != nil {
		t.Fatal(err)
	}
	// SQLite exposes its file path without reaching into the blob store implementation.
	var seq int
	var name, path string
	if err := st.DB().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(filepath.Dir(path), "blobs", b.Digest[:2], b.Digest[2:4], b.Digest)
	if err := os.WriteFile(local, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if stats, err := Fetch(context.Background(), st.DB(), blobs, target); err != nil || stats.Fetched != 1 {
		t.Fatal(stats, err)
	}
	f, _, err := blobs.Open(b.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// S3's shared transport needs ReadSeeker for its hashing pass without buffering.
func TestUploadPreservesSeekableSource(t *testing.T) {
	st, blobs, target, key := fixture(t)
	b := addBlob(t, st, blobs, "seekable", strings.NewReader("synthetic ciphertext"))
	probe := &seekableTarget{Target: target}
	stats, err := Sync(context.Background(), st.DB(), blobs, probe, key, []Object{b})
	if err != nil || stats.Uploaded != 1 || !probe.seekable {
		t.Fatal("upload lost streaming seek support", stats, err)
	}
}

type seekableTarget struct {
	offsite.Target
	seekable bool
}

func (t *seekableTarget) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	_, t.seekable = r.(io.ReadSeeker)
	return t.Target.Put(ctx, name, r, size)
}
