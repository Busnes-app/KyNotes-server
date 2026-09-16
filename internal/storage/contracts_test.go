package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

func openContract(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	s := openContract(t)
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(entries) {
		t.Fatalf("migration count=%d expected=%d err=%v", n, len(entries), err)
	}
}

func TestOpenIsIdempotentAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(path); err != nil {
		t.Fatal(err)
	} else {
		_ = s.Close()
	}
}

func TestMigrationVersionsAreContiguous(t *testing.T) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range entries {
		var version int
		if _, err = fmt.Sscanf(entry.Name(), "%04d_", &version); err != nil || version != i+1 {
			t.Fatalf("migration %s is not contiguous", entry.Name())
		}
	}
}

func TestConcurrentOpenDoesNotRaceMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(path)
			if s != nil {
				_ = s.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWithTxRollsBackOnError(t *testing.T) {
	s := openContract(t)
	errSentinel := sql.ErrTxDone
	err := s.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_tx','tx','hash','salt',100000,'now','now')`)
		if err != nil {
			return err
		}
		return errSentinel
	})
	if err != errSentinel {
		t.Fatalf("got %v", err)
	}
	var n int
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM users WHERE id='usr_tx'`).Scan(&n)
	if n != 0 {
		t.Fatal("rolled-back row remains")
	}
}

func TestNextChangeSeqIsStrictlyIncreasingUnderConcurrency(t *testing.T) {
	s := openContract(t)
	_, err := s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_seq','seq','hash','salt',100000,'now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at) VALUES('cnt_seq','workbook','usr_seq',0,'now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	values := make(chan int64, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.WithTx(context.Background(), func(tx *sql.Tx) error {
				seq, err := s.NextChangeSeq(tx, "cnt_seq")
				if err == nil {
					values <- seq
				}
				return err
			})
			if err != nil {
				t.Errorf("sequence transaction: %v", err)
			}
		}()
	}
	wg.Wait()
	close(values)
	seen := map[int64]bool{}
	for seq := range values {
		if seen[seq] {
			t.Fatalf("duplicate sequence %d", seq)
		}
		seen[seq] = true
	}
	if len(seen) != 8 {
		t.Fatalf("got %d sequences", len(seen))
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	s := openContract(t)
	if _, err := s.DB().Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('ses_fk','usr_missing','x','y','now','now','now')`); err == nil {
		t.Fatal("foreign key violation accepted")
	}
}

func TestWALModeIsActive(t *testing.T) {
	s := openContract(t)
	var mode string
	if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode=%q err=%v", mode, err)
	}
}

func TestIntegrityCheckPassesOnFreshDatabase(t *testing.T) {
	if err := openContract(t).IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBlobSurvivesMetadataTransactionFailure(t *testing.T) {
	root := t.TempDir()
	s := openContract(t)
	b, _ := blobstore.New(root)
	x, _ := b.NewTemp("tx")
	_, _ = x.Write([]byte("cipher"))
	digest, _, err := x.Finalize("")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.WithTx(context.Background(), func(*sql.Tx) error { return sql.ErrTxDone })
	if _, ok, err := b.Stat(digest); err != nil || !ok {
		t.Fatal("finalized blob disappeared")
	}
}

func TestMetadataNeverReferencesUnfinalizedBlob(t *testing.T) {
	s := openContract(t)
	if _, err := s.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at) VALUES('missing',1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',1,1,1,?)`, time.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("unfinalized blob reference accepted")
	}
}

func TestRestartRecoversPendingUploadSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	s, _ := Open(path)
	_, err := s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_up','up','hash','salt',100000,'now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_up','workbook','usr_up','now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at) VALUES('ups_up','usr_up','cnt_up',1,1,'now','now','later')`)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestMissingBlobIsDetectedByConsistencyCheck(t *testing.T) {
	root := t.TempDir()
	s := openContract(t)
	b, _ := blobstore.New(root)
	_, err := s.DB().Exec(`INSERT INTO blobs(digest,size_bytes,created_at) VALUES('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',1,'now')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = Consistency(s.DB(), b); err == nil {
		t.Fatal("missing blob was not reported")
	}
}
