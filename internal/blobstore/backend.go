package blobstore

import (
	"errors"
	"io"
)

// Backend is the blob seam from tenancy N15. Single mode always receives New's volume store;
// the gated multi-mode router supplies request-owned org/object/part adapters.
type Backend interface {
	NewTemp(id string) (Temporary, error)
	Reopen(id string) (Temporary, error)
	Open(digest string) (io.ReadSeekCloser, int64, error)
	Stat(digest string) (int64, bool, error)
	Delete(digest string) error
	ListDigests() ([]string, error)
	DeletePrefix(prefix string) error
}

// Temporary is an upload/save in progress. Backends own persistence; callers own the stream
// until Finalize or Abort. In particular, no filesystem handle escapes this contract.
type Temporary interface {
	io.Writer
	io.ReaderAt
	io.Closer
	Digest() string
	Size() int64
	Truncate(int64) error
	Finalize(expected string) (digest string, size int64, err error)
	Abort() error
}

var _ Backend = (*Store)(nil)
var _ Temporary = (*Temp)(nil)

// The volume backend is single-tenant only. It has no org-prefix purge operation, and must
// never become a multi-tenant fallback when an object backend is unavailable.
func (*Store) DeletePrefix(string) error { return errors.ErrUnsupported }
