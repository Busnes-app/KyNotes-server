package storage

import (
	"database/sql"
	"strings"
	"testing"
)

// The catalog questions tests ask, answered on whichever backend the store runs.

func catalogTables(t *testing.T, s *Store) []string {
	t.Helper()
	q := `SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'`
	if s.pg {
		q = `SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'`
	}
	rows, err := s.db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	return names
}

// catalogColumn reports a column's NOT NULL and its default as SQL text ("" for none).
func catalogColumn(s *Store, table, column string) (notNull bool, def string, err error) {
	var d sql.NullString
	if s.pg {
		var nullable string
		err = s.db.QueryRow(`SELECT is_nullable,column_default FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? AND column_name=?`, table, column).Scan(&nullable, &d)
		return nullable == "NO", strings.TrimSuffix(d.String, "::text"), err
	}
	var n int
	err = s.db.QueryRow(`SELECT "notnull",dflt_value FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&n, &d)
	return n == 1, d.String, err
}

func catalogColumns(t *testing.T, s *Store, table string) map[string]bool {
	t.Helper()
	q := `SELECT name FROM pragma_table_info(?)`
	if s.pg {
		q = `SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?`
	}
	rows, err := s.db.Query(q, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got[n] = true
	}
	return got
}

func catalogTrigger(s *Store, name, table string) bool {
	q := `SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name=? AND tbl_name=?`
	if s.pg {
		q = `SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE g.tgname=? AND c.relname=? AND c.relnamespace=current_schema()::regnamespace`
	}
	var n int
	return s.db.QueryRow(q, name, table).Scan(&n) == nil && n == 1
}
