// Package mirror replicates immutable ciphertext blobs; it never sees note plaintext.
package mirror

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/offsite"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

type Object struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size_bytes"`
}
type Stats struct {
	Uploaded   int    `json:"uploaded"`
	Skipped    int    `json:"skipped"`
	Failed     int    `json:"failed"`
	Fetched    int    `json:"fetched"`
	Missing    int    `json:"missing"`
	FirstError string `json:"first_error,omitempty"`
}

var ErrIncomplete = errors.New("ciphertext blob recovery is incomplete")

// TargetKey includes account-relative namespaces and SFTP host identity, but excludes
// passwords and secret keys. Changing a password alone should not resend every blob.
func TargetKey(c offsite.Config) string {
	base := offsite.Key(c)
	u, err := url.Parse(c.URL)
	if err != nil || base == "" {
		return ""
	}
	namespace := ""
	if strings.EqualFold(u.Scheme, "sftp") || strings.EqualFold(u.Scheme, "smb") {
		namespace = c.AccessKey
		if u.User != nil {
			namespace = u.User.Username()
		}
	}
	hostKey := ""
	if strings.EqualFold(u.Scheme, "sftp") {
		hostKey = c.HostKey
	}
	sum := sha256.Sum256([]byte(base + "\x00" + namespace + "\x00" + hostKey))
	return hex.EncodeToString(sum[:])
}
func List(ctx context.Context, db *sql.DB) ([]Object, error) {
	rows, err := db.QueryContext(ctx, `SELECT digest,size_bytes FROM blobs ORDER BY digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Object{}
	for rows.Next() {
		var b Object
		if err = rows.Scan(&b.Digest, &b.Size); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func Pending(db *sql.DB, key string) (int, error) {
	var n int
	err := db.QueryRow(`SELECT count(*) FROM blobs b WHERE NOT EXISTS(SELECT 1 FROM blob_replicas r WHERE r.digest=b.digest AND r.target=?)`, key).Scan(&n)
	return n, err
}
func valid(b Object) bool {
	raw, err := hex.DecodeString(b.Digest)
	return err == nil && len(raw) == 32 && b.Digest == strings.ToLower(b.Digest) && b.Size >= 0 && b.Size < math.MaxInt64
}
func (s *Stats) failure(code string, missing bool) {
	s.Failed++
	if missing {
		s.Missing++
	}
	if s.FirstError == "" {
		s.FirstError = code
	}
}
func (s Stats) err() error {
	if s.Failed > 0 || s.Missing > 0 {
		return ErrIncomplete
	}
	return nil
}

// Sync uses the caller's snapshot inventory when supplied. It never forgets a digest
// just because live GC removed its row after that capsule was collected.
func Sync(ctx context.Context, db *sql.DB, blobs *blobstore.Store, target offsite.Target, key string, inventory []Object) (Stats, error) {
	stats := Stats{}
	if key == "" {
		return stats, errors.New("blob target identity required")
	}
	for _, b := range inventory {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if !valid(b) {
			stats.failure("invalid_inventory", false)
			continue
		}
		var done int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM blob_replicas WHERE digest=? AND target=?`, b.Digest, key).Scan(&done); err != nil {
			return stats, err
		}
		// ponytail: acknowledgements avoid rereading every remote blob each run. Upgrade path:
		// a periodic remote scrub if the operator needs detection of later target-side deletion.
		if done != 0 {
			stats.Skipped++
			continue
		}
		if err := put(ctx, blobs, target, b); err != nil {
			stats.failure("upload_or_verification_failed", errors.Is(err, os.ErrNotExist))
			continue
		}
		_, err := db.ExecContext(ctx, `INSERT INTO blob_replicas(digest,target,uploaded_at) VALUES(?,?,?) ON CONFLICT(digest) DO UPDATE SET target=excluded.target,uploaded_at=excluded.uploaded_at`, b.Digest, key, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			stats.failure("replica_record_failed", false)
			continue
		}
		stats.Uploaded++
	}
	return stats, stats.err()
}
func put(ctx context.Context, blobs *blobstore.Store, target offsite.Target, b Object) error {
	source, size, err := blobs.Open(b.Digest)
	if err != nil {
		return err
	}
	defer source.Close()
	if size != b.Size {
		return blobstore.ErrCorruptBlob
	}
	// Preserve ReadSeeker: S3 hashes then rewinds to stream. Shared transports
	// already enforce cancellation while reading Put bodies.
	err = target.Put(ctx, "blobs/"+b.Digest, source, size)
	if errors.Is(err, offsite.ErrObjectExists) {
		return verifyExisting(ctx, target, b)
	}
	return err
}
func verifyExisting(ctx context.Context, target offsite.Target, b Object) error {
	reader, err := target.Get(ctx, "blobs/"+b.Digest)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(contextReader{ctx, reader}, b.Size+1))
	closeErr := reader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != b.Size || hex.EncodeToString(hash.Sum(nil)) != b.Digest {
		return blobstore.ErrDigestMismatch
	}
	return nil
}

// Fetch repairs absent or corrupt local content from the restored database inventory.
// Replica rows are an upload optimization, never restore authority.
func Fetch(ctx context.Context, db *sql.DB, blobs *blobstore.Store, target offsite.Target) (Stats, error) {
	inventory, err := List(ctx, db)
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{}
	for _, b := range inventory {
		if err = ctx.Err(); err != nil {
			return stats, err
		}
		if !valid(b) {
			stats.failure("invalid_inventory", false)
			continue
		}
		existing, size, e := blobs.Open(b.Digest)
		if e == nil {
			existing.Close()
			if size == b.Size {
				stats.Skipped++
				continue
			}
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) && !errors.Is(e, blobstore.ErrCorruptBlob) {
			stats.failure("local_read_failed", false)
			continue
		}
		if e = fetch(ctx, blobs, target, b); e != nil {
			stats.failure("fetch_or_digest_failed", errors.Is(e, os.ErrNotExist))
			continue
		}
		stats.Fetched++
	}
	return stats, stats.err()
}
func fetch(ctx context.Context, blobs *blobstore.Store, target offsite.Target, b Object) error {
	reader, err := target.Get(ctx, "blobs/"+b.Digest)
	if err != nil {
		return err
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	temp, err := blobs.NewTemp("restore-" + hex.EncodeToString(id[:]))
	if err != nil {
		reader.Close()
		return err
	}
	defer temp.Abort()
	n, readErr := io.Copy(temp, io.LimitReader(contextReader{ctx, reader}, b.Size+1))
	closeErr := reader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != b.Size || temp.Digest() != b.Digest {
		return blobstore.ErrDigestMismatch
	}
	// The replacement was verified before removing a corrupt old local copy.
	if _, ok, e := blobs.Stat(b.Digest); e != nil {
		return e
	} else if ok {
		file, _, e := blobs.Open(b.Digest)
		if e == nil {
			file.Close()
		} else if errors.Is(e, blobstore.ErrCorruptBlob) {
			if e = blobs.Delete(b.Digest); e != nil {
				return e
			}
		} else {
			return e
		}
	}
	_, _, err = temp.Finalize(b.Digest)
	return err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}
