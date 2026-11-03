package blobstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
)

var ErrDigestMismatch = errors.New("digest mismatch")
var ErrCorruptBlob = errors.New("corrupt blob")

type Store struct{ root string }
type Temp struct {
	f     *os.File
	path  string
	store *Store
	h     hash.Hash
	size  int64
}

func (t *Temp) Close() error { return t.f.Close() }

func New(root string) (*Store, error) {
	for _, p := range []string{filepath.Join(root, "blobs"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			return nil, err
		}
	}
	return &Store{root}, nil
}
func (s *Store) path(d string) string { return filepath.Join(s.root, "blobs", d[:2], d[2:4], d) }
func (s *Store) NewTemp(id string) (*Temp, error) {
	if id == "" || filepath.Base(id) != id {
		return nil, os.ErrInvalid
	}
	p := filepath.Join(s.root, "tmp", id+".part")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	return &Temp{f: f, path: p, store: s, h: sha256.New()}, nil
}
func (t *Temp) Write(p []byte) (int, error) {
	n, e := t.f.Write(p)
	if n > 0 {
		_, _ = t.h.Write(p[:n])
		t.size += int64(n)
	}
	return n, e
}
func (t *Temp) ReadAt(p []byte, off int64) (int, error) { return t.f.ReadAt(p, off) }
func (t *Temp) Digest() string                          { return hex.EncodeToString(t.h.Sum(nil)) }
func (t *Temp) Size() int64                             { return t.size }
func (t *Temp) Finalize(expected string) (string, int64, error) {
	if err := t.f.Sync(); err != nil {
		return "", 0, err
	}
	d := t.Digest()
	if expected != "" && expected != d {
		_ = t.Abort()
		return "", 0, ErrDigestMismatch
	}
	dest := t.store.path(d)
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return "", 0, err
	}
	if st, err := os.Stat(dest); err == nil {
		if st.Size() != t.size {
			return "", 0, ErrCorruptBlob
		}
		f, _, verifyErr := t.store.Open(d)
		if verifyErr != nil {
			return "", 0, ErrCorruptBlob
		}
		_ = f.Close()
		_ = t.Abort()
		return d, t.size, nil
	}
	if err := os.Rename(t.path, dest); err != nil {
		return "", 0, err
	}
	if dir, err := os.Open(filepath.Dir(dest)); err == nil {
		if err = dir.Sync(); err != nil {
			_ = dir.Close()
			return "", 0, err
		}
		_ = dir.Close()
	}
	t.path = ""
	_ = t.f.Close()
	return d, t.size, nil
}
func (t *Temp) Abort() error {
	if t == nil {
		return nil
	}
	_ = t.f.Close()
	return os.Remove(t.path)
}
func (s *Store) Open(d string) (io.ReadSeekCloser, int64, error) {
	if len(d) != 64 {
		return nil, 0, os.ErrNotExist
	}
	if _, err := hex.DecodeString(d); err != nil {
		return nil, 0, os.ErrNotExist
	}
	f, e := os.Open(s.path(d))
	if e != nil {
		return nil, 0, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, 0, e
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		_ = f.Close()
		return nil, 0, e
	}
	if hex.EncodeToString(h.Sum(nil)) != d {
		_ = f.Close()
		return nil, 0, ErrCorruptBlob
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		_ = f.Close()
		return nil, 0, e
	}
	return f, st.Size(), nil
}
func (s *Store) Stat(d string) (int64, bool, error) {
	if len(d) != 64 {
		return 0, false, nil
	}
	if _, err := hex.DecodeString(d); err != nil {
		return 0, false, nil
	}
	st, e := os.Stat(s.path(d))
	if os.IsNotExist(e) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, e
	}
	return st.Size(), true, nil
}
func (s *Store) Delete(d string) error {
	if len(d) != 64 {
		return os.ErrInvalid
	}
	if _, err := hex.DecodeString(d); err != nil {
		return os.ErrInvalid
	}
	e := os.Remove(s.path(d))
	if os.IsNotExist(e) {
		return nil
	}
	return e
}
func (s *Store) Reopen(id string) (*Temp, error) {
	p := filepath.Join(s.root, "tmp", id+".part")
	f, e := os.OpenFile(p, os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	t := &Temp{f: f, path: p, store: s, h: sha256.New()}
	if _, e = f.Seek(0, 0); e != nil {
		return nil, e
	}
	n, e := io.Copy(t.h, f)
	if e != nil {
		return nil, e
	}
	t.size = n
	_, _ = f.Seek(0, 2)
	return t, nil
}

// Truncate drops everything past n bytes and re-hashes what stays.
func (t *Temp) Truncate(n int64) error {
	if err := t.f.Truncate(n); err != nil {
		return err
	}
	if _, err := t.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	t.h.Reset()
	size, err := io.Copy(t.h, t.f)
	if err != nil {
		return err
	}
	t.size = size
	_, err = t.f.Seek(0, io.SeekEnd)
	return err
}
func (s *Store) ListDigests() ([]string, error) {
	var out []string
	root := filepath.Join(s.root, "blobs")
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if len(name) == 64 {
			if _, de := hex.DecodeString(name); de == nil {
				out = append(out, name)
			}
		}
		return nil
	})
	return out, e
}
