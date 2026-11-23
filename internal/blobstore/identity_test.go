package blobstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func identityDatabase(t *testing.T) *sql.DB {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	s, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.DB().Exec(`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	return s.DB()
}
func controlFiles(root string) (func(context.Context, string) ([]byte, error), func(context.Context, string, []byte) error) {
	read := func(ctx context.Context, name string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return os.ReadFile(filepath.Join(root, name))
	}
	create := func(ctx context.Context, name string, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		// Match conditional object PUT: creation becomes visible only with complete contents.
		f, err := os.CreateTemp(root, ".control-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(value); err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		return os.Link(f.Name(), path)
	}

	return read, create
}
func TestReplicaStoreIdentityConcurrentFreshStartsAndPrivateStoreRefusal(t *testing.T) {
	db := identityDatabase(t)
	ctx := context.Background()
	root := t.TempDir()
	read, create := controlFiles(root)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- blobstore.VerifySharedIdentity(ctx, db, read, create) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var before string
	if err := db.QueryRow(`SELECT value FROM server_settings WHERE key='blob_probe'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	privateRead, privateCreate := controlFiles(t.TempDir())
	if err := blobstore.VerifySharedIdentity(ctx, db, privateRead, privateCreate); !errors.Is(err, blobstore.ErrStoreIdentity) {
		t.Fatalf("private store admitted: %v", err)
	}
	var after string
	if err := db.QueryRow(`SELECT value FROM server_settings WHERE key='blob_probe'`).Scan(&after); err != nil || before != after {
		t.Fatal("refused replica advanced probe")
	}
	// Another install's marker also refuses, even if it points at the same bucket root.
	other := identityDatabase(t)
	if err := blobstore.VerifySharedIdentity(ctx, other, read, create); !errors.Is(err, blobstore.ErrStoreIdentity) {
		t.Fatalf("other install admitted: %v", err)
	}
}
func TestReplicaStoreIdentityCrashBeforeMarkerIsRepairable(t *testing.T) {
	db := identityDatabase(t)
	ctx := context.Background()
	id := strings.Repeat("A", 43)
	if _, err := db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES('blob_store_id',?,'')`, id); err != nil {
		t.Fatal(err)
	}
	read, create := controlFiles(t.TempDir())
	if err := blobstore.VerifySharedIdentity(ctx, db, read, create); err != nil {
		t.Fatal(err)
	}
	got, err := read(ctx, "store-id")
	if err != nil || !bytes.Equal(got, []byte(id)) {
		t.Fatalf("retained identity not repaired: %q %v", got, err)
	}
}
func TestReplicaStoreIdentityFreshPrivateStoresAdmitOnlyFirstWinner(t *testing.T) {
	db := identityDatabase(t)
	ctx := context.Background()
	firstRead, firstCreate := controlFiles(t.TempDir())
	secondRead, secondCreate := controlFiles(t.TempDir())
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, run := range []func() error{func() error { return blobstore.VerifySharedIdentity(ctx, db, firstRead, firstCreate) }, func() error { return blobstore.VerifySharedIdentity(ctx, db, secondRead, secondCreate) }} {
		wg.Add(1)
		go func(run func() error) { defer wg.Done(); results <- run() }(run)
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, blobstore.ErrStoreIdentity) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("fresh private stores accepted %d replicas", accepted)
	}
}

func TestReplicaStoreIdentityRechecksAChangedProbePointer(t *testing.T) {
	db := identityDatabase(t)
	ctx := context.Background()
	read, create := controlFiles(t.TempDir())
	if err := blobstore.VerifySharedIdentity(ctx, db, read, create); err != nil {
		t.Fatal(err)
	}
	var old, id string
	if err := db.QueryRow(`SELECT value FROM server_settings WHERE key='blob_probe'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT value FROM server_settings WHERE key='blob_store_id'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	newer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	raced := false
	racingRead := func(ctx context.Context, name string) ([]byte, error) {
		if name == "probes/"+old && !raced {
			raced = true
			if err := create(ctx, "probes/"+newer, []byte(id)); err != nil {
				return nil, err
			}
			if _, err := db.ExecContext(ctx, `UPDATE server_settings SET value=? WHERE key='blob_probe'`, newer); err != nil {
				return nil, err
			}
			return nil, os.ErrNotExist
		}
		return read(ctx, name)
	}
	if err := blobstore.VerifySharedIdentity(ctx, db, racingRead, create); err != nil {
		t.Fatalf("concurrent startup caused false refusal: %v", err)
	}
	if !raced {
		t.Fatal("probe change was not exercised")
	}
}

func TestStoreIdentitySingleModeDoesNoControlIO(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "single.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	read := func(context.Context, string) ([]byte, error) {
		t.Error("single mode read replica control object")
		return nil, os.ErrNotExist
	}
	create := func(context.Context, string, []byte) error {
		t.Error("single mode wrote replica control object")
		return nil
	}
	if err := blobstore.VerifySharedIdentity(context.Background(), st.DB(), read, create); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM server_settings WHERE key IN ('blob_store_id','blob_probe','blob_probe_prev')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("single mode wrote identity state: %d %v", n, err)
	}
}
