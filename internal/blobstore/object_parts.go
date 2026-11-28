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

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
)

// PutPart writes one complete chunk under the org/upload/index key. The caller holds the
// upload session lock and owns DB counter admission. An identical retry reuses bytes; a
// rolled-back counter explicitly drops its uncommitted tail before accepting another body.
func (s *Objects) PutPart(ctx context.Context, id string, index int64, body io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, putDeadline)
	defer cancel()
	key, err := UploadPartKey(s.cell, s.org, id, index)
	if err != nil {
		return err
	}
	if size <= 0 || size > s.maxBytes {
		return os.ErrInvalid
	}
	file, err := s.snapshot(ctx, body, size, "")
	if err != nil {
		return err
	}
	defer file.Close()
	existing, err := s.client.Head(ctx, key, "")
	if err == nil {
		if existing.Size != size {
			return ErrCorruptBlob
		}
		old, _, err := s.openKey(ctx, key, "")
		if err != nil {
			return err
		}
		same := old.digest == file.digest
		closeErr := old.Close()
		if !same {
			return ErrCorruptBlob
		}
		return closeErr
	}
	if !errors.Is(err, shareds3.ErrNotFound) {
		return err
	}
	_, err = s.client.Put(ctx, key, file, size)
	return err
}

func (s *Objects) OpenPart(ctx context.Context, id string, index int64) (io.ReadSeekCloser, int64, error) {
	key, err := UploadPartKey(s.cell, s.org, id, index)
	if err != nil {
		return nil, 0, err
	}
	return s.openKey(ctx, key, "")
}

// AssembleParts verifies exact part sizes/order and the optional final ciphertext digest
// into one bounded private stream. No live part is removed before the final DB commit.
func (s *Objects) AssembleParts(ctx context.Context, id string, totalBytes, chunkBytes int64, expected string) (io.ReadSeekCloser, string, error) {
	if _, err := UploadPartKey(s.cell, s.org, id, 0); err != nil {
		return nil, "", err
	}
	if totalBytes <= 0 || totalBytes > s.maxBytes || chunkBytes <= 0 || chunkBytes > s.maxBytes {
		return nil, "", os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	file, err := os.CreateTemp(s.scratch, ".kynotes-object-")
	if err != nil {
		return nil, "", err
	}
	private := &privateObject{file: file, path: file.Name()}
	keep := false
	defer func() {
		if !keep {
			_ = private.Close()
		}
	}()
	hash := sha256.New()
	for offset, index := int64(0), int64(0); offset < totalBytes; index++ {
		size := totalBytes - offset
		if size > chunkBytes {
			size = chunkBytes
		}
		key, _ := UploadPartKey(s.cell, s.org, id, index) // org/id validated above; index is nonnegative
		body, meta, err := s.client.Get(ctx, key, "")
		if err != nil {
			return nil, "", err
		}
		if meta.Size != size {
			body.Close()
			return nil, "", ErrCorruptBlob
		}
		n, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, size+1))
		closeErr := body.Close()
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if copyErr != nil {
			return nil, "", copyErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if n != size {
			return nil, "", ErrCorruptBlob
		}
		offset += n
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if expected != "" && digest != expected {
		return nil, "", ErrDigestMismatch
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	private.digest = digest
	keep = true
	return private, digest, nil
}

func (s *Objects) partPrefix(id string) (string, error) {
	key, err := UploadPartKey(s.cell, s.org, id, 0)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(key, "0"), nil
}

// DeletePartsFrom is explicit cleanup of a DB-uncommitted tail, under the upload lock.
func (s *Objects) DeletePartsFrom(ctx context.Context, id string, first int64) error {
	if first < 0 {
		return os.ErrInvalid
	}
	prefix, err := s.partPrefix(id)
	if err != nil {
		return err
	}
	keys, err := s.listKeys(ctx, prefix)
	if err != nil {
		return err
	}
	var doomed []string
	for _, key := range keys {
		index, err := strconv.ParseInt(strings.TrimPrefix(key, prefix), 10, 64)
		canonical, keyErr := UploadPartKey(s.cell, s.org, id, index)
		if err != nil || keyErr != nil || key != canonical {
			return ErrCorruptBlob
		}
		if index >= first {
			doomed = append(doomed, key)
		}
	}
	for _, key := range doomed {
		if err := s.client.DeleteAllVersions(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

// DeleteParts runs after finalize commit, cancellation or expiry, under the upload lock.
func (s *Objects) DeleteParts(ctx context.Context, id string) error {
	prefix, err := s.partPrefix(id)
	if err != nil {
		return err
	}
	return s.client.DeletePrefix(ctx, prefix)
}
