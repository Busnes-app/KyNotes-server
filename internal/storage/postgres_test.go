package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

func requirePostgres(t *testing.T) *Store {
	t.Helper()
	if !OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	return openFresh(t)
}

// The PostgreSQL schema has every SQLite table and column, bar the ones it leaves out on
// purpose. A SQLite migration without its postgres/ counterpart fails here (and at open).
func TestPostgresSchemaMatchesSQLite(t *testing.T) {
	pg := requirePostgres(t)
	lite, err := openSQLite(filepath.Join(t.TempDir(), "db.sqlite"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	omitted := map[string]bool{"cleanup_audit_slots": true, "blob_replicas": true, "comments.cleanup_padding": true, "containers.cleanup_padding": true, "sealed_share_links.cleanup_padding": true}
	shape := func(s *Store) []string {
		var out []string
		for _, table := range catalogTables(t, s) {
			if omitted[table] {
				continue
			}
			out = append(out, table)
			for column := range catalogColumns(t, s, table) {
				if !omitted[table+"."+column] {
					out = append(out, table+"."+column)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	a, b := shape(lite), shape(pg)
	if len(a) != len(b) {
		t.Fatalf("SQLite has %d tables and columns, PostgreSQL %d:\nSQLite %v\nPostgreSQL %v", len(a), len(b), a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("schemas differ at %s (SQLite) / %s (PostgreSQL)", a[i], b[i])
		}
	}
}

// N3: every write transaction takes the one writer lock, so a read-modify-write is never
// interleaved, as under SQLite's immediate transactions. Reads take no lock.
func TestPostgresWritersAreSerialised(t *testing.T) {
	s := requirePostgres(t)
	if _, err := s.db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES('n3','0','t')`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.WithTx(context.Background(), func(tx *sql.Tx) error {
				var v int
				if err := tx.QueryRow(`SELECT CAST(value AS BIGINT) FROM server_settings WHERE key='n3'`).Scan(&v); err != nil {
					return err
				}
				time.Sleep(2 * time.Millisecond)
				_, err := tx.Exec(`UPDATE server_settings SET value=? WHERE key='n3'`, strconv.Itoa(v+1))
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	// A read never waits for the writers.
	done := make(chan error, 1)
	go func() {
		tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
		if err == nil {
			var v string
			err = tx.QueryRow(`SELECT value FROM server_settings WHERE key='n3'`).Scan(&v)
			tx.Rollback()
		}
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	var v string
	if err := s.db.QueryRow(`SELECT value FROM server_settings WHERE key='n3'`).Scan(&v); err != nil || v != "16" {
		t.Fatalf("value=%s (%v), want 16: writers interleaved", v, err)
	}
}
