package backup

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// The native PostgreSQL backup for multi mode (tenancy open question 3): storage's archive,
// sealed in 1 MiB AES-256-GCM frames under a key derived per archive from the operator's
// 32-byte backup key. Each frame's associated data binds the archive salt, its index and the
// final flag, so a reordered, dropped, truncated or extended archive fails to open.
const (
	archiveMagic = "KYNOTES-PGB1\n"
	frameBytes   = 1 << 20
	saltBytes    = 32
	// BackupKeyBytes is the operator's backup key length.
	BackupKeyBytes = 32
)

var errArchiveSealed = errors.New("postgres backup: the archive does not open with this key or is damaged")

// BackupPostgres writes the sealed archive of store to w.
func BackupPostgres(ctx context.Context, db *sql.DB, key []byte, w io.Writer) (storage.ArchiveSummary, error) {
	sw, err := newSealWriter(w, key)
	if err != nil {
		return storage.ArchiveSummary{}, err
	}
	bw := bufio.NewWriterSize(sw, frameBytes)
	sum, err := storage.BackupPostgres(ctx, db, bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = sw.Close()
	}
	return sum, err
}

// RestorePostgres loads a sealed archive into a new, empty target and commits the restore
// fence with it, so the target never holds restored rows without the fence and replay gate.
func RestorePostgres(ctx context.Context, db *sql.DB, key []byte, r io.Reader) (storage.ArchiveSummary, error) {
	or, err := newOpenReader(r, key)
	if err != nil {
		return storage.ArchiveSummary{}, err
	}
	return storage.RestorePostgres(ctx, db, or, func(tx *sql.Tx) error { return fenceRestoredTx(ctx, tx) })
}

func archiveAEAD(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != BackupKeyBytes {
		return nil, errors.New("postgres backup: the backup key must be 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, key, salt, "kynotes pg archive v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func frameAAD(salt []byte, index uint64, final bool) []byte {
	aad := append([]byte(archiveMagic), salt...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

type sealWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	salt  []byte
	index uint64
	buf   []byte
}

func newSealWriter(w io.Writer, key []byte) (*sealWriter, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := archiveAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, archiveMagic); err != nil {
		return nil, err
	}
	if _, err := w.Write(salt); err != nil {
		return nil, err
	}
	return &sealWriter{w: w, aead: aead, salt: salt}, nil
}

func (s *sealWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		take := min(frameBytes-len(s.buf), len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		if len(s.buf) == frameBytes {
			if err := s.frame(false); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// Close writes the final frame (possibly empty); without it the archive does not open.
func (s *sealWriter) Close() error { return s.frame(true) }

func (s *sealWriter) frame(final bool) error {
	sealed := s.aead.Seal(nil, nil, s.buf, frameAAD(s.salt, s.index, final))
	head := []byte{0}
	if final {
		head[0] = 1
	}
	head = binary.BigEndian.AppendUint32(head, uint32(len(sealed)))
	if _, err := s.w.Write(head); err != nil {
		return err
	}
	if _, err := s.w.Write(sealed); err != nil {
		return err
	}
	s.index++
	s.buf = s.buf[:0]
	return nil
}

type openReader struct {
	r     io.Reader
	aead  cipher.AEAD
	salt  []byte
	index uint64
	plain []byte
	done  bool
}

func newOpenReader(r io.Reader, key []byte) (*openReader, error) {
	head := make([]byte, len(archiveMagic)+saltBytes)
	if _, err := io.ReadFull(r, head); err != nil || string(head[:len(archiveMagic)]) != archiveMagic {
		return nil, errors.New("postgres backup: not a KyNotes PostgreSQL backup")
	}
	salt := head[len(archiveMagic):]
	aead, err := archiveAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	return &openReader{r: r, aead: aead, salt: salt}, nil
}

func (o *openReader) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.done {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}

func (o *openReader) next() error {
	var head [5]byte
	if _, err := io.ReadFull(o.r, head[:]); err != nil {
		return errArchiveSealed
	}
	final := head[0] == 1
	size := binary.BigEndian.Uint32(head[1:])
	if head[0] > 1 || size < uint32(o.aead.Overhead()) || size > frameBytes+uint32(o.aead.Overhead()) {
		return errArchiveSealed
	}
	sealed := make([]byte, size)
	if _, err := io.ReadFull(o.r, sealed); err != nil {
		return errArchiveSealed
	}
	plain, err := o.aead.Open(nil, nil, sealed, frameAAD(o.salt, o.index, final))
	if err != nil {
		return errArchiveSealed
	}
	if final {
		var extra [1]byte
		if _, err := io.ReadFull(o.r, extra[:]); err != io.EOF {
			return errArchiveSealed
		}
		o.done = true
	}
	o.index++
	o.plain = plain
	return nil
}
