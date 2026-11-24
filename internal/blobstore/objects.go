package blobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
)

// Objects owns permanent ciphertext operations for one resolved org through the shared S3
// client. It is the permanent-blob portion of N15, not a complete Backend or startup adapter.
// Callers authorize first and hold the org/digest session lock through PUT/claim or row-drop/
// DELETE. No object I/O may run under the global database writer lock.
type Objects struct {
	client       *shareds3.Client
	org, scratch string
	maxBytes     int64
}

// putDeadline bounds every Put/PutPart call, from entry, so a write admitted before an erasure
// or purge cannot reach the provider after LatePutWindow. Callers pass already-received bytes
// and admit the org under the session lock immediately before the call.
var putDeadline = 5 * time.Minute

// LatePutWindow is how long after its writers are fenced an org's prefix can still gain a
// late PUT: the put deadline plus SigV4's 15-minute request-age limit, which also covers a
// provider that commits after the client gave up. Unqualified on a real provider.
const LatePutWindow = 20 * time.Minute

func (Objects) String() string   { return "blobstore.Objects" }
func (Objects) GoString() string { return "blobstore.Objects" }

func NewObjects(client *shareds3.Client, org, scratch string, maxBytes int64) (*Objects, error) {
	if _, err := OrgPrefix(org); err != nil {
		return nil, err
	}
	if client == nil || maxBytes <= 0 || maxBytes == 1<<63-1 {
		return nil, os.ErrInvalid
	}
	return &Objects{client: client, org: org, scratch: scratch, maxBytes: maxBytes}, nil
}

// Put verifies a bounded private snapshot before any PUT. The caller's session lock makes
// HEAD/verify/PUT safe for a content-addressed key; it does not replace exclusive control PUTs.
func (s *Objects) Put(ctx context.Context, digest string, body io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, putDeadline)
	defer cancel()
	key, err := BlobKey(s.org, digest)
	if err != nil {
		return err
	}
	if size < 0 || size > s.maxBytes {
		return os.ErrInvalid
	}
	file, err := s.snapshot(ctx, body, size, digest)
	if err != nil {
		return err
	}
	defer file.Close()
	existing, err := s.client.Head(ctx, key, "")
	if err == nil {
		if existing.Size != size {
			return ErrCorruptBlob
		}
		verified, _, err := s.Open(ctx, digest)
		if err != nil {
			return err
		}
		return verified.Close()
	}
	if !errors.Is(err, shareds3.ErrNotFound) {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = s.client.Put(ctx, key, file, size)
	return err
}

// Open downloads and hashes before exposing seekable bytes. Each request owns its temporary
// file; Close removes it. This is neither a persistent cache nor a volume fallback.
func (s *Objects) Open(ctx context.Context, digest string) (io.ReadSeekCloser, int64, error) {
	key, err := BlobKey(s.org, digest)
	if err != nil {
		return nil, 0, err
	}
	return s.openKey(ctx, key, digest)
}

func (s *Objects) openKey(ctx context.Context, key, digest string) (*privateObject, int64, error) {
	body, meta, err := s.client.Get(ctx, key, "")
	if err != nil {
		return nil, 0, err
	}
	defer body.Close()
	if meta.Size < 0 || meta.Size > s.maxBytes {
		return nil, 0, ErrCorruptBlob
	}
	file, err := s.snapshot(ctx, body, meta.Size, digest)
	if errors.Is(err, ErrDigestMismatch) {
		err = ErrCorruptBlob
	}
	if err != nil {
		return nil, 0, err
	}
	return file, meta.Size, nil
}

func (s *Objects) Stat(ctx context.Context, digest string) (int64, bool, error) {
	key, err := BlobKey(s.org, digest)
	if err != nil {
		return 0, false, err
	}
	meta, err := s.client.Head(ctx, key, "")
	if errors.Is(err, shareds3.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if meta.Size < 0 || meta.Size > s.maxBytes {
		return 0, false, ErrCorruptBlob
	}
	return meta.Size, true, nil
}

// Delete is explicit removal after references are gone. Remove every physical version of the
// one immutable ciphertext key; this does not prune any kept logical object_versions row.
func (s *Objects) Delete(ctx context.Context, digest string) error {
	key, err := BlobKey(s.org, digest)
	if err != nil {
		return err
	}
	return s.client.DeleteAllVersions(ctx, key)
}

// Purge deletes only this org's namespace after its audited deletion has fenced all writers.
// Provider retention/replica refusals remain errors; no success is inferred from a partial purge.
func (s *Objects) Purge(ctx context.Context) error {
	prefix, _ := OrgPrefix(s.org) // validated at construction
	return s.client.DeletePrefix(ctx, prefix)
}

func (s *Objects) ListDigests(ctx context.Context) ([]string, error) {
	prefix, _ := OrgPrefix(s.org)
	prefix += "blobs/"
	keys, err := s.listKeys(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		_, digest, ok := strings.Cut(key[len(prefix):], "/")
		if ok {
			_, digest, ok = strings.Cut(digest, "/")
		}
		canonical, keyErr := BlobKey(s.org, digest)
		if !ok || keyErr != nil || key != canonical {
			return nil, ErrCorruptBlob
		}
		out = append(out, digest)
	}
	return out, nil
}

// Stored lists the org's blobs and uploads with the provider's modification time, the latest
// part's for an upload. A zero time is unknown age: the orphan sweep never deletes on it.
func (s *Objects) Stored(ctx context.Context) (blobs, uploads map[string]time.Time, err error) {
	prefix, _ := OrgPrefix(s.org)
	objects, err := s.listObjects(ctx, prefix)
	if err != nil {
		return nil, nil, err
	}
	blobs, uploads = map[string]time.Time{}, map[string]time.Time{}
	for _, o := range objects {
		rest := o.Key[len(prefix):]
		if strings.HasPrefix(rest, "blobs/") {
			digest := rest[strings.LastIndexByte(rest, '/')+1:]
			if key, err := BlobKey(s.org, digest); err != nil || key != o.Key {
				return nil, nil, ErrCorruptBlob
			}
			blobs[digest] = o.LastModified
			continue
		}
		id, index, _ := strings.Cut(strings.TrimPrefix(rest, "uploads/"), "/")
		n, err := strconv.ParseInt(index, 10, 64)
		if key, keyErr := UploadPartKey(s.org, id, n); err != nil || keyErr != nil || key != o.Key {
			return nil, nil, ErrCorruptBlob
		}
		switch t, seen := uploads[id]; {
		case !seen, !t.IsZero() && (o.LastModified.IsZero() || o.LastModified.After(t)):
			uploads[id] = o.LastModified // the newest part, or unknown if any part's age is
		}
	}
	return blobs, uploads, nil
}

func (s *Objects) listKeys(ctx context.Context, prefix string) ([]string, error) {
	objects, err := s.listObjects(ctx, prefix)
	keys := make([]string, len(objects))
	for i, o := range objects {
		keys[i] = o.Key
	}
	return keys, err
}

func (s *Objects) listObjects(ctx context.Context, prefix string) ([]shareds3.Object, error) {
	var keys []shareds3.Object
	seenKeys, seenTokens := map[string]bool{}, map[string]bool{}
	token := ""
	for {
		page, err := s.client.ListObjects(ctx, prefix, token)
		if err != nil {
			return nil, err
		}
		for _, object := range page.Objects {
			if seenKeys[object.Key] {
				return nil, ErrCorruptBlob
			}
			seenKeys[object.Key] = true
			keys = append(keys, object)
		}
		if page.Next == "" {
			return keys, nil
		}
		if seenTokens[page.Next] {
			return nil, ErrCorruptBlob
		}
		seenTokens[page.Next] = true
		token = page.Next
	}
}

type privateObject struct {
	file   *os.File
	path   string
	digest string
}

func (p *privateObject) Read(body []byte) (int, error) { return p.file.Read(body) }
func (p *privateObject) Seek(offset int64, whence int) (int64, error) {
	return p.file.Seek(offset, whence)
}
func (p *privateObject) Close() error { return errors.Join(p.file.Close(), os.Remove(p.path)) }

func (s *Objects) snapshot(ctx context.Context, body io.Reader, size int64, digest string) (*privateObject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(s.scratch, ".kynotes-object-")
	if err != nil {
		return nil, err
	}
	private := &privateObject{file: file, path: file.Name()}
	keep := false
	defer func() {
		if !keep {
			_ = private.Close()
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, size+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	private.digest = hex.EncodeToString(hash.Sum(nil))
	if n != size || (digest != "" && private.digest != digest) {
		return nil, ErrDigestMismatch
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	keep = true
	return private, nil
}
