package httpapi

import (
	"database/sql"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Test helpers that write SQL a backend's own way, for tests that run on SQLite and on
// PostgreSQL (KYNOTES_TEST_DATABASE_URL).

// refuseTrigger makes every timing ("BEFORE INSERT", "BEFORE UPDATE OF col", "BEFORE DELETE")
// on table fail with msg, when cond (SQL over NEW or OLD, "" for always) holds.
func refuseTrigger(t *testing.T, db *sql.DB, name, timing, table, cond, msg string) {
	t.Helper()
	q := `CREATE TRIGGER ` + name + ` ` + timing + ` ON ` + table
	if storage.IsPostgres(db) {
		if cond == "" {
			cond = "true"
		}
		q = `CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + cond + ` THEN RAISE EXCEPTION '` + msg + `'; END IF; RETURN COALESCE(NEW, OLD); END $$; ` + q + ` FOR EACH ROW EXECUTE FUNCTION ` + name + `()`
	} else {
		if cond != "" {
			q += ` WHEN ` + cond
		}
		q += ` BEGIN SELECT RAISE(ABORT,'` + msg + `'); END`
	}
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func dropTrigger(t *testing.T, db *sql.DB, name, table string) {
	t.Helper()
	q := `DROP TRIGGER ` + name
	if storage.IsPostgres(db) {
		q += ` ON ` + table
	}
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func testTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	q := `SELECT name FROM sqlite_master WHERE type='table'`
	if storage.IsPostgres(db) {
		q = `SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'`
	}
	rows, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// afterInsertRun runs stmt after each insert into table for which cond ("" for always) holds.
func afterInsertRun(t *testing.T, db *sql.DB, name, table, cond, stmt string) {
	t.Helper()
	q := `CREATE TRIGGER ` + name + ` AFTER INSERT ON ` + table
	if storage.IsPostgres(db) {
		if cond == "" {
			cond = "true"
		}
		q = `CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ` + cond + ` THEN ` + stmt + `; END IF; RETURN NEW; END $$; ` + q + ` FOR EACH ROW EXECUTE FUNCTION ` + name + `()`
	} else {
		if cond != "" {
			q += ` WHEN ` + cond
		}
		q += ` BEGIN ` + stmt + `; END`
	}
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

// rowOrder orders rows as inserted: rowid on SQLite, the physical ctid on PostgreSQL, which
// follows insertion for rows a test inserted and never updated.
func rowOrder(db *sql.DB) string {
	if storage.IsPostgres(db) {
		return "ctid"
	}
	return "rowid"
}

// columnsQuery lists a table's columns in declared order; it takes the table as its argument.
func columnsQuery(db *sql.DB) string {
	if storage.IsPostgres(db) {
		return `SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? ORDER BY ordinal_position`
	}
	return `SELECT name FROM pragma_table_info(?) ORDER BY cid`
}
