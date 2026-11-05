package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct {
	db   *sql.DB
	path string
}

// ErrSchemaNewer: the database was migrated by a newer release than this binary.
var ErrSchemaNewer = errors.New("database schema is newer than this release")

var migrateMu sync.Mutex

func (s *Store) DB() *sql.DB { return s.db }

func Open(path string) (*Store, error) { return open(path, true) }

// OpenUnmigrated opens and checks a database without migrating it, so a copy keeps the schema
// its data was written with (a pre-upgrade copy made with the newer image stays restorable).
func OpenUnmigrated(path string) (*Store, error) { return open(path, false) }

// ErrSchemaOlder: the database predates this binary's migrations.
var ErrSchemaOlder = errors.New("database schema is older than this release")

// OpenCurrent opens without migrating and refuses a database whose schema is not exactly this
// release's, so a backup command never upgrades the live database it is copying.
func OpenCurrent(path string) (*Store, error) {
	s, err := open(path, false)
	if err != nil {
		return nil, err
	}
	rows, err := migrationFS.ReadDir("migrations")
	var applied int
	if err == nil {
		err = s.db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&applied)
	}
	switch {
	case err != nil:
	case applied > len(rows):
		err = fmt.Errorf("%w: database schema %d, this release knows %d; run the release that wrote it", ErrSchemaNewer, applied, len(rows))
	case applied < len(rows):
		err = fmt.Errorf("%w: database schema %d, this release expects %d; back it up with the release that wrote it, or start this release once to upgrade it first", ErrSchemaOlder, applied, len(rows))
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func open(path string, migrate bool) (*Store, error) {
	// synchronous(FULL): a commit the server acknowledged survives power loss; clients drop their
	// queued copy on that acknowledgement.
	d, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)", path))
	if err != nil {
		return nil, err
	}
	s := &Store{db: d, path: path}
	if migrate {
		if err = s.migrate(); err != nil {
			d.Close()
			return nil, err
		}
	}
	if err = s.IntegrityCheck(context.Background()); err != nil {
		d.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) migrate() error {
	migrateMu.Lock()
	defer migrateMu.Unlock()
	return s.migratePending(true)
}
func (s *Store) migratePending(preflight bool) error {
	rows, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name() < rows[j].Name() })
	// A database migrated by a newer release must not be run by this older one.
	var applied int
	_ = s.db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&applied)
	if applied > len(rows) {
		return fmt.Errorf("%w: database schema %d, this release knows %d; run the newer release or restore a copy made before the upgrade", ErrSchemaNewer, applied, len(rows))
	}
	if preflight && applied > 0 && applied < cleanupSchemaVersion {
		if err := s.preflightCleanupUpgrade(); err != nil {
			return err
		}
	}
	if applied == len(rows) {
		return nil
	}
	// All pending migrations commit together. If the live capacity recheck differs
	// from the staged preflight, an old binary still sees its exact original schema.
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for i, f := range rows {
		var v int
		if _, err = fmt.Sscanf(f.Name(), "%04d_", &v); err != nil {
			return err
		}
		if v != i+1 {
			return fmt.Errorf("migration versions are not contiguous at%04d", v)
		}
		if v <= applied {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			return err
		}
		if _, err = tx.Exec(string(b)); err != nil {
			return err
		}
		if v == cleanupSchemaVersion {
			if err = initializeCleanupSlotsTx(tx); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", v, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if applied < cleanupSchemaVersion {
		used, err := DatabaseBytes(tx)
		if err != nil {
			return err
		}
		if used > CleanupDatabaseBudget {
			return fmt.Errorf("%w: complete migration%d bytes, budget%d; reduce pages/notebooks with the old release", ErrCleanupCapacity, used, CleanupDatabaseBudget)
		}
	}
	return tx.Commit()
}
func (s *Store) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
func (s *Store) IntegrityCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("integrity check: %s", result)
	}
	return nil
}
func (s *Store) NextChangeSeq(tx *sql.Tx, containerID string) (int64, error) {
	var n int64
	err := tx.QueryRow("UPDATE containers SET change_seq=change_seq+1 WHERE id=? RETURNING change_seq", containerID).Scan(&n)
	return n, err
}

// A private staged copy runs the complete pending migration chain before any live schema
// change. The caller owns the directory lock at startup; the real migration rechecks its
// physical budget in its own immediate transaction before committing.
func (s *Store) preflightCleanupUpgrade() error {
	scratch, err := os.MkdirTemp(filepath.Dir(s.path), "snapshot-cleanup-preflight-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	path := filepath.Join(scratch, "kynotes.sqlite")
	if err = recoveryclient.SQLiteSnapshot(context.Background(), s.db, path); err != nil {
		return err
	}
	staged, err := open(path, false)
	if err != nil {
		return err
	}
	defer staged.Close()
	if err = staged.migratePending(false); err != nil {
		return fmt.Errorf("upgrade refused before live migration: %w", err)
	}
	return staged.IntegrityCheck(context.Background())
}
