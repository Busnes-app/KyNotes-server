package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// SessionLock pins a PostgreSQL connection for the lock's whole lifetime. It never holds N3's
// write transaction while a worker or storage operation waits on the network. The owner context
// follows the caller; the elected worker probes its otherwise idle connection.
// Session pooling is required.
func SessionLock(parent context.Context, db *sql.DB, name string, wait bool) (*SessionLease, bool, error) {
	conn, err := db.Conn(parent)
	if err != nil {
		return nil, false, err
	}
	var schema string
	if err := conn.QueryRowContext(parent, `SELECT current_schema()`).Scan(&schema); err != nil {
		conn.Close()
		return nil, false, err
	}
	key := sessionKey(schema, name)
	acquired := true
	if wait {
		_, err = conn.ExecContext(parent, `SELECT pg_advisory_lock(?)`, key)
	} else {
		err = conn.QueryRowContext(parent, `SELECT pg_try_advisory_lock(?)`, key).Scan(&acquired)
	}
	if err != nil || !acquired {
		if err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		conn.Close()
		return nil, false, err
	}
	owned, cancel := context.WithCancel(parent)
	release := sync.OnceFunc(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		var unlocked bool
		err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock(?)`, key).Scan(&unlocked)
		if err != nil || !unlocked {
			// Never return a possibly locked session to the pool, where a new owner could re-enter it.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
	})
	if owned.Err() != nil {
		release()
		return nil, false, errors.New("session lock cancelled during admission")
	}
	return &SessionLease{Context: owned, conn: conn, Release: release}, true, nil
}

// SessionLease keeps the request's reads and short write transaction on the lock's connection.
// Exec's pgdialect autowrap still acquires N3. No extra pool connection is needed by a request.
type SessionLease struct {
	Context context.Context
	conn    *sql.Conn
	Release func()
}

func (l *SessionLease) QueryRow(q string, args ...any) *sql.Row {
	return l.conn.QueryRowContext(l.Context, q, args...)
}
func (l *SessionLease) Query(q string, args ...any) (*sql.Rows, error) {
	return l.conn.QueryContext(l.Context, q, args...)
}
func (l *SessionLease) Exec(q string, args ...any) (sql.Result, error) {
	return l.conn.ExecContext(l.Context, q, args...)
}
func (l *SessionLease) Begin() (*sql.Tx, error) { return l.conn.BeginTx(l.Context, nil) }

// Ping is used by the elected worker only; request leases use this connection for their SQL.
func (l *SessionLease) Ping(ctx context.Context) error { return l.conn.PingContext(ctx) }

func sessionKey(schema, name string) int64 {
	hash := sha256.Sum256([]byte("kynotes/session/" + schema + "/" + name))
	return int64(binary.BigEndian.Uint64(hash[:8]))
}

// Lock takes an additional session lock on the existing connection, so an upload can
// hold its part lock and digest claim lock even with a one-connection pool. Release the
// additional lock before releasing this lease. Network I/O remains outside N3.
func (l *SessionLease) Lock(name string) (func(), error) {
	var schema string
	if err := l.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		return nil, err
	}
	key := sessionKey(schema, name)
	if _, err := l.Exec(`SELECT pg_advisory_lock(?)`, key); err != nil {
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		return nil, err
	}
	return sync.OnceFunc(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var unlocked bool
		err := l.conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock(?)`, key).Scan(&unlocked)
		if err != nil || !unlocked {
			_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}), nil
}
