package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct{ db *sql.DB }

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
	s := &Store{db: d}
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
	for i, f := range rows {
		var v int
		if _, err = fmt.Sscanf(f.Name(), "%04d_", &v); err != nil {
			return err
		}
		if v != i+1 {
			return fmt.Errorf("migration versions are not contiguous at %04d", v)
		}
		var n int
		_ = s.db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&n)
		if v <= n {
			continue
		}
		b, e := migrationFS.ReadFile("migrations/" + f.Name())
		if e != nil {
			return e
		}
		tx, e := s.db.Begin()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(string(b)); e == nil {
			_, e = tx.Exec("INSERT INTO schema_migrations(version, applied_at) VALUES(?,?)", v, time.Now().UTC().Format(time.RFC3339))
		}
		if e != nil {
			_ = tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	return nil
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
