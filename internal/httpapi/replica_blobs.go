package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// replicaBlobs is a route-owned resolver. Each handler gets its own requestObjects; no
// request identity, lock or temporary stream is shared between handlers or replicas.
type replicaBlobs struct {
	unavailableBlobs
	db     *sql.DB
	stores storage.ObjectStores
}

type requestObjects struct {
	unavailableBlobs
	db               *sql.DB
	stores           storage.ObjectStores
	r                *http.Request
	objects          *blobstore.Objects
	org              string
	upload, blob     *storage.SessionLease
	inherited        bool
	blobUnlock       func()
	uploadID, digest string
	size             int64
}

func requestBlobs(r *http.Request, backend blobstore.Backend) (blobstore.Backend, func()) {
	resolver, ok := backend.(*replicaBlobs)
	if !ok {
		return backend, func() {}
	}
	b := &requestObjects{db: resolver.db, stores: resolver.stores, r: r}
	return b, b.close
}
func (b *requestObjects) close() {
	// A finalized/failed upload has no live parts. Failed cleanup is retried by the orphan
	// sweep after its session expires; never remove parts while a claim transaction runs.
	if b.uploadID != "" && b.objects != nil && b.upload != nil && !b.inherited {
		var status string
		if b.upload.QueryRow(`SELECT status FROM upload_sessions WHERE id=? AND org_id=?`, b.uploadID, b.org).Scan(&status) == nil && status != "pending" {
			_ = b.objects.DeleteParts(b.upload.Context, b.uploadID)
		}
	}
	if b.blobUnlock != nil {
		b.blobUnlock()
		b.blob = nil
	}
	if b.blob != nil {
		b.blob.Release()
	}
	if b.upload != nil && !b.inherited {
		b.upload.Release()
	}
}
func (b *requestObjects) resolve() error {
	if b.objects != nil {
		return nil
	}
	if uid, ok := auth.CredentialUserID(b.r); ok {
		if err := b.db.QueryRowContext(b.r.Context(), `SELECT u.org_id FROM users u WHERE u.id=? AND `+storage.OrgServes("u.org_id"), uid).Scan(&b.org); err != nil {
			return err
		}
	} else {
		// This path is reached only after the public share handler has validated its token.
		sum := sha256.Sum256([]byte(b.r.PathValue("token")))
		if err := b.db.QueryRowContext(b.r.Context(), `SELECT c.org_id FROM share_links l JOIN objects o ON o.id=l.object_id JOIN containers c ON c.id=o.container_id WHERE l.token_hash=? AND l.revoked_at='' AND `+storage.OrgServes("c.org_id"), hex.EncodeToString(sum[:])).Scan(&b.org); err != nil {
			return err
		}
	}
	var err error
	b.objects, err = b.stores(b.r.Context(), b.org)
	return err
}
func (b *requestObjects) Open(digest string) (io.ReadSeekCloser, int64, error) {
	if err := b.resolve(); err != nil {
		return nil, 0, err
	}
	return b.objects.Open(b.r.Context(), digest)
}
func (b *requestObjects) Stat(digest string) (int64, bool, error) {
	// claimBlob may only ask about bytes this request successfully PUT under the digest lock.
	// It runs inside N3: no network call is permitted here.
	if b.blob == nil || digest != b.digest {
		return 0, false, errors.New("object claim has no verified write")
	}
	return b.size, true, nil
}
func (b *requestObjects) Delete(string) error { return errors.ErrUnsupported }
func (b *requestObjects) NewTemp(id string) (blobstore.Temporary, error) {
	if ids.Validate("ups", id) == nil {
		return b.Reopen(id)
	}
	if err := b.resolve(); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", ".kynotes-request-")
	if err != nil {
		return nil, err
	}
	return &objectTemp{b: b, file: f}, nil
}
func (b *requestObjects) Reopen(id string) (blobstore.Temporary, error) {
	if err := b.resolve(); err != nil {
		return nil, err
	}
	if ids.Validate("ups", id) != nil {
		return nil, os.ErrInvalid
	}
	if b.upload == nil {
		lease, _, err := storage.SessionLock(b.r.Context(), b.db, storage.UploadLockName(b.org, id), true)
		if err != nil {
			return nil, err
		}
		b.upload = lease
	}
	b.uploadID = id
	var received, chunk, declared int64
	var status string
	if err := b.upload.QueryRow(`SELECT received_bytes,chunk_bytes,declared_bytes,status FROM upload_sessions WHERE id=? AND org_id=?`, id, b.org).Scan(&received, &chunk, &declared, &status); err != nil {
		return nil, err
	}
	if chunk <= 0 || received < 0 || received > declared {
		return nil, os.ErrInvalid
	}
	return &objectTemp{b: b, id: id, size: received, chunk: chunk, declared: declared}, nil
}
func (b *requestObjects) begin() (*sql.Tx, error) {
	if b.blob != nil {
		return b.blob.Begin()
	}
	if b.upload != nil {
		return b.upload.Begin()
	}
	return b.db.BeginTx(b.r.Context(), nil)
}
func (b *requestObjects) checkServes(tx *sql.Tx, cid string) error {
	var serves int
	if err := tx.QueryRow(`SELECT count(*) FROM containers c JOIN orgs o ON o.id=c.org_id WHERE c.id=? AND o.id=? AND `+storage.OrgServes("o.id"), cid, b.org).Scan(&serves); err != nil {
		return err
	}
	if serves != 1 {
		return errors.New("org no longer serves")
	}
	return nil
}
func (b *requestObjects) exec(q string, args ...any) (sql.Result, error) {
	if b.blob != nil {
		return b.blob.Exec(q, args...)
	}
	if b.upload != nil {
		return b.upload.Exec(q, args...)
	}
	return b.db.ExecContext(b.r.Context(), q, args...)
}
func blobExec(ctx context.Context, db *sql.DB, backend blobstore.Backend, q string, args ...any) (sql.Result, error) {
	if b, ok := backend.(*requestObjects); ok {
		return b.exec(q, args...)
	}
	return db.ExecContext(ctx, q, args...)
}
func blobBegin(db *sql.DB, backend blobstore.Backend) (*sql.Tx, error) {
	if b, ok := backend.(*requestObjects); ok {
		return b.begin()
	}
	return db.Begin()
}
func blobTransaction(db *sql.DB, backend blobstore.Backend, fn func(*sql.Tx) error) error {
	tx, err := blobBegin(db, backend)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// objectTemp is either one request's private body or a shared upload's numbered parts.
// Only body bytes are local, never a persistent blob or upload fallback.
type objectTemp struct {
	b                     *requestObjects
	file                  *os.File
	id                    string
	size, chunk, declared int64
	digest                string
}

func (t *objectTemp) Size() int64    { return t.size }
func (t *objectTemp) Digest() string { return t.digest }
func (t *objectTemp) Write(raw []byte) (int, error) {
	if t.file != nil {
		n, err := t.file.Write(raw)
		t.size += int64(n)
		return n, err
	}
	if len(raw) == 0 || int64(len(raw)) > t.chunk || t.size+int64(len(raw)) > t.declared || t.size%t.chunk != 0 {
		return 0, os.ErrInvalid
	}
	// A part may outlive a rolled-back DB counter; replace only that uncommitted tail.
	if err := t.admit(); err != nil {
		return 0, err
	}
	index := t.size / t.chunk
	if err := t.b.objects.DeletePartsFrom(t.b.upload.Context, t.id, index); err != nil {
		return 0, err
	}
	if err := t.b.objects.PutPart(t.b.upload.Context, t.id, index, bytes.NewReader(raw), int64(len(raw))); err != nil {
		return 0, err
	}
	t.size += int64(len(raw))
	return len(raw), nil
}
func (t *objectTemp) admit() error {
	var count int
	err := t.b.upload.QueryRow(`SELECT count(*) FROM upload_sessions us WHERE us.id=? AND us.org_id=? AND us.status='pending' AND `+storage.OrgServes("us.org_id"), t.id, t.b.org).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("upload no longer admitted")
	}
	return nil
}
func (t *objectTemp) ReadAt(raw []byte, offset int64) (int, error) {
	if t.file != nil {
		return t.file.ReadAt(raw, offset)
	}
	if offset < 0 || offset%t.chunk != 0 {
		return 0, os.ErrInvalid
	}
	body, size, err := t.b.objects.OpenPart(t.b.upload.Context, t.id, offset/t.chunk)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	if int64(len(raw)) != size {
		return 0, io.ErrUnexpectedEOF
	}
	return io.ReadFull(body, raw)
}
func (t *objectTemp) Truncate(size int64) error {
	if t.file != nil {
		if err := t.file.Truncate(size); err != nil {
			return err
		}
		t.size = size
		_, err := t.file.Seek(size, io.SeekStart)
		return err
	}
	if size < 0 || size > t.size || size%t.chunk != 0 {
		return os.ErrInvalid
	}
	if err := t.b.objects.DeletePartsFrom(t.b.upload.Context, t.id, size/t.chunk); err != nil {
		return err
	}
	t.size = size
	return nil
}
func (t *objectTemp) Finalize(expected string) (string, int64, error) {
	var body io.ReadSeekCloser
	if t.file != nil {
		if _, err := t.file.Seek(0, io.SeekStart); err != nil {
			return "", 0, err
		}
		h := sha256.New()
		if _, err := io.Copy(h, t.file); err != nil {
			return "", 0, err
		}
		t.digest = hex.EncodeToString(h.Sum(nil))
		if expected != "" && expected != t.digest {
			return "", 0, blobstore.ErrDigestMismatch
		}
		if _, err := t.file.Seek(0, io.SeekStart); err != nil {
			return "", 0, err
		}
		body = t.file
	} else {
		if t.size != t.declared {
			return "", 0, io.ErrUnexpectedEOF
		}
		if err := t.admit(); err != nil {
			return "", 0, err
		}
		var err error
		if t.size == 0 {
			sum := sha256.Sum256(nil)
			t.digest = hex.EncodeToString(sum[:])
			if expected != "" && expected != t.digest {
				return "", 0, blobstore.ErrDigestMismatch
			}
			body = emptyObject{bytes.NewReader(nil)}
		} else {
			body, t.digest, err = t.b.objects.AssembleParts(t.b.upload.Context, t.id, t.size, t.chunk, expected)
		}
		if err != nil {
			return "", 0, err
		}
		defer body.Close()
	}
	var lease *storage.SessionLease
	var err error
	if t.b.upload != nil {
		lease = t.b.upload
		t.b.blobUnlock, err = lease.Lock(storage.BlobLockName(t.b.org, t.digest))
	} else {
		lease, _, err = storage.SessionLock(t.b.r.Context(), t.b.db, storage.BlobLockName(t.b.org, t.digest), true)
	}
	if err != nil {
		return "", 0, err
	}
	t.b.blob = lease
	var serves int
	if err := lease.QueryRow(`SELECT count(*) FROM orgs o WHERE o.id=? AND `+storage.OrgServes("o.id"), t.b.org).Scan(&serves); err != nil {
		return "", 0, err
	}
	if serves != 1 {
		return "", 0, errors.New("org no longer serves")
	}
	if err := t.b.objects.Put(lease.Context, t.digest, body, t.size); err != nil {
		return "", 0, err
	}
	t.b.digest, t.b.size = t.digest, t.size
	if t.file != nil {
		_ = t.Close()
	}
	return t.digest, t.size, nil
}
func (t *objectTemp) Close() error {
	if t.file == nil {
		return nil
	}
	f := t.file
	t.file = nil
	return errors.Join(f.Close(), os.Remove(f.Name()))
}
func (t *objectTemp) Abort() error {
	if t.file != nil {
		return t.Close()
	}
	return t.b.objects.DeleteParts(t.b.upload.Context, t.id)
}

var _ blobstore.Backend = (*requestObjects)(nil)
var _ blobstore.Temporary = (*objectTemp)(nil)

func uploadLockName(backend blobstore.Backend, id string) string {
	if b, ok := backend.(*requestObjects); ok {
		if err := b.resolve(); err != nil {
			return "refused-upload/" + id
		}
		return storage.UploadLockName(b.org, id)
	}
	return "upload/" + id
}

// An unresolved route backend fails closed if a new caller forgets request binding.
type unavailableBlobs struct{}

func (unavailableBlobs) NewTemp(string) (blobstore.Temporary, error) {
	return nil, errors.ErrUnsupported
}
func (unavailableBlobs) Reopen(string) (blobstore.Temporary, error) {
	return nil, errors.ErrUnsupported
}
func (unavailableBlobs) Open(string) (io.ReadSeekCloser, int64, error) {
	return nil, 0, errors.ErrUnsupported
}
func (unavailableBlobs) Stat(string) (int64, bool, error) { return 0, false, errors.ErrUnsupported }
func (unavailableBlobs) Delete(string) error              { return errors.ErrUnsupported }
func (unavailableBlobs) ListDigests() ([]string, error)   { return nil, errors.ErrUnsupported }
func (unavailableBlobs) DeletePrefix(string) error        { return errors.ErrUnsupported }

type emptyObject struct{ *bytes.Reader }

func (emptyObject) Close() error { return nil }
