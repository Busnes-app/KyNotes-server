package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage/pgdialect"
)

//go:embed postgres/*.sql
var postgresFS embed.FS

// Postgres reports whether the store runs on PostgreSQL (multi-tenant mode only).
func (s *Store) Postgres() bool { return s.pg }

// IsPostgres reports whether db is a PostgreSQL store's handle, for code that holds only the
// *sql.DB and must skip a SQLite-only mechanism.
func IsPostgres(db interface{ Driver() driver.Driver }) bool {
	_, ok := db.Driver().(pgdialect.Driver)
	return ok
}

// OpenPostgres opens the PostgreSQL database at dsn and brings its schema up to date. Errors
// name only the host and database: the DSN carries a password.
func OpenPostgres(dsn string) (*Store, error) { return openPostgres(dsn, "", true) }

func openPostgres(dsn, searchPath string, migrate bool) (*Store, error) {
	where := pgdialect.Describe(dsn)
	if searchPath != "" {
		dsn = withSearchPath(dsn, searchPath)
	}
	c, err := pgdialect.NewConnector(dsn, false)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(c)
	db.SetMaxOpenConns(runtime.NumCPU() + 4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to PostgreSQL at %s: %w", where, err)
	}
	s := &Store{db: db, pg: true}
	_, s.migrationKey = pgdialect.LockKeys(searchPath)
	if migrate {
		err = s.migratePostgres()
		if err == nil {
			err = s.ensureOrgs()
		}
	} else {
		var ok bool
		if err = db.QueryRow(`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&ok); err == nil && !ok {
			err = errors.New("not initialized")
		}
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("PostgreSQL at %s: %w", where, err)
	}
	return s, nil
}

// migratePostgres applies the postgres/ files above the recorded version, under a session
// advisory lock on one pinned connection, so replicas starting together migrate once and a
// holder that dies releases the lock with its connection.
func (s *Store) migratePostgres() error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(?)`, s.migrationKey); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, `SELECT pg_advisory_unlock(?)`, s.migrationKey)
	var applied int
	var exists bool
	if err = conn.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		if err = conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&applied); err != nil {
			return err
		}
	}
	files, err := postgresFS.ReadDir("postgres")
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	latest, err := migrationCount()
	if err != nil {
		return err
	}
	if applied > latest {
		return fmt.Errorf("%w: database schema %d, this release knows %d", ErrSchemaNewer, applied, latest)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, f := range files {
		var v int
		if _, err = fmt.Sscanf(f.Name(), "%04d_", &v); err != nil {
			return err
		}
		if v <= applied {
			continue
		}
		b, err := postgresFS.ReadFile("postgres/" + f.Name())
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("%s: %w", f.Name(), err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, v, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		applied = v
	}
	if applied != latest {
		return fmt.Errorf("the PostgreSQL schema stops at %d; SQLite migrations reach %d", applied, latest)
	}
	return tx.Commit()
}

func migrationCount() (int, error) {
	rows, err := migrationFS.ReadDir("migrations")
	return len(rows), err
}

func withSearchPath(dsn, searchPath string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn // NewConnector reports it
	}
	q := u.Query()
	q.Set("search_path", searchPath)
	u.RawQuery = q.Encode()
	return u.String()
}

// Tests run every store on PostgreSQL when KYNOTES_TEST_DATABASE_URL is set: Open(path) opens
// a schema named after path, so two Opens of one path share it as two handles share a file,
// and tests stay isolated. The database must be UTF8 with the C locale, as CI's is.
func testDatabaseURL() string {
	if !testing.Testing() {
		return ""
	}
	return os.Getenv("KYNOTES_TEST_DATABASE_URL")
}

// OnPostgresTest reports whether this test binary runs its stores on PostgreSQL.
func OnPostgresTest() bool { return testDatabaseURL() != "" }

// SkipOnPostgres skips a test about SQLite itself when the suite runs on PostgreSQL.
func SkipOnPostgres(t testing.TB, reason string) {
	t.Helper()
	if OnPostgresTest() {
		t.Skip("SQLite only: " + reason)
	}
}

// Drop the schemas of finished tests (their directory is gone), once per test binary.
var testSetup = sync.OnceValue(func() error {
	db, err := sql.Open("kynotespg", testDatabaseURL())
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT nspname, COALESCE(obj_description(oid,'pg_namespace'),'') FROM pg_namespace WHERE nspname LIKE 'kn\_%'`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var name, note string
		if err := rows.Scan(&name, &note); err != nil {
			rows.Close()
			return err
		}
		if dir, ok := strings.CutPrefix(note, "path:"); ok {
			if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
				stale = append(stale, name)
			}
		}
	}
	rows.Close()
	for _, name := range stale {
		if _, err := db.Exec(`DROP SCHEMA IF EXISTS "` + name + `" CASCADE`); err != nil {
			return err
		}
	}
	return nil
})

func testSchema(path string) (schema, note string, err error) {
	if path == "" || strings.HasPrefix(path, ":memory:") {
		var b [8]byte
		_, _ = rand.Read(b[:])
		return "kn_mem_" + hex.EncodeToString(b[:]), "memory:", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return "kn_" + hex.EncodeToString(sum[:12]), "path:" + abs, nil
}

func openTestPostgres(path string, migrate bool) (*Store, error) {
	dsn := testDatabaseURL()
	if err := testSetup(); err != nil {
		return nil, fmt.Errorf("preparing the test database: %w", err)
	}
	schema, note, err := testSchema(path)
	if err != nil {
		return nil, err
	}
	if migrate {
		db, err := sql.Open("kynotespg", dsn)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec(`CREATE SCHEMA IF NOT EXISTS "` + schema + `"; COMMENT ON SCHEMA "` + schema + `" IS '` + strings.ReplaceAll(note, "'", "''") + `'`)
		db.Close()
		if err != nil {
			return nil, err
		}
	}
	s, err := openPostgres(dsn, schema, migrate)
	if err == nil {
		s.path = path
	}
	return s, err
}
