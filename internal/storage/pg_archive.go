package storage

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Busnes-app/kynotes-server/internal/storage/pgdialect"
)

// The PostgreSQL archive (tenancy open question 3): a JSON header line, every table's COPY
// text rows in foreign-key order each ended by a `\.` line, then a JSON trailer line. One
// REPEATABLE READ snapshot yields every row, so the blob rows (the org-qualified object
// references) agree with the notes that use them. Encryption belongs to the caller.
const archiveFormat = "kynotes-pg-archive/1"

// ArchiveSummary is what a backup wrote or a restore loaded.
type ArchiveSummary struct {
	Schema  int
	TakenAt string // database clock, RFC 3339
	Rows    map[string]int64
}

type archiveHeader struct {
	Format  string         `json:"format"`
	Schema  int            `json:"schema"`
	TakenAt string         `json:"taken_at"`
	Tables  []archiveTable `json:"tables"`
}

type archiveTable struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

type archiveTrailer struct {
	Rows      map[string]int64 `json:"rows"`
	Sequences map[string]int64 `json:"sequences"` // next value to hand out
}

// BackupPostgres writes the archive of the whole database db (multi mode) to w.
func BackupPostgres(ctx context.Context, db *sql.DB, w io.Writer) (ArchiveSummary, error) {
	var sum ArchiveSummary
	if !IsPostgres(db) {
		return sum, errors.New("postgres archive: PostgreSQL only")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return sum, err
	}
	defer conn.Close()
	err = conn.Raw(func(dc any) error {
		pc := pgdialect.PgxConn(dc)
		if _, err := pc.Exec(ctx, `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
			return err
		}
		defer pc.Exec(context.WithoutCancel(ctx), `ROLLBACK`)
		var mode string
		if err := pc.QueryRow(ctx, `SELECT COALESCE((SELECT value FROM server_settings WHERE key='tenancy_mode'),'single')`).Scan(&mode); err != nil {
			return err
		}
		if mode != "multi" {
			return errors.New("postgres archive: recorded multi tenancy only")
		}
		var taken time.Time
		if err := pc.QueryRow(ctx, `SELECT COALESCE(MAX(version),0), now() FROM schema_migrations`).Scan(&sum.Schema, &taken); err != nil {
			return err
		}
		sum.TakenAt = taken.UTC().Format(time.RFC3339)
		tables, err := archiveTables(ctx, pc)
		if err != nil {
			return err
		}
		head, _ := json.Marshal(archiveHeader{archiveFormat, sum.Schema, sum.TakenAt, tables})
		if _, err := w.Write(append(head, '\n')); err != nil {
			return err
		}
		sum.Rows = map[string]int64{}
		for _, t := range tables {
			tag, err := pc.PgConn().CopyTo(ctx, w, `COPY `+copyTarget(t)+` TO STDOUT`)
			if err != nil {
				return fmt.Errorf("postgres archive: %s: %w", t.Name, err)
			}
			sum.Rows[t.Name] = tag.RowsAffected()
			if _, err := io.WriteString(w, "\\.\n"); err != nil {
				return err
			}
		}
		seqs, err := archiveSequences(ctx, pc)
		if err != nil {
			return err
		}
		tail, _ := json.Marshal(archiveTrailer{sum.Rows, seqs})
		_, err = w.Write(append(tail, '\n'))
		return err
	})
	return sum, err
}

// RestorePostgres loads an archive into db, a fresh target of the same schema, in one
// transaction with user triggers off (the rows were valid where they were written; usage
// counters must not count twice) and foreign keys checked. fence runs in that transaction
// after the triggers are back on; if anything fails nothing is loaded.
func RestorePostgres(ctx context.Context, db *sql.DB, r io.Reader, fence func(*sql.Tx) error) (ArchiveSummary, error) {
	var sum ArchiveSummary
	if !IsPostgres(db) {
		return sum, errors.New("postgres archive: PostgreSQL only")
	}
	in := bufio.NewReaderSize(r, 1<<20)
	var head archiveHeader
	if err := readArchiveLine(in, &head); err != nil || head.Format != archiveFormat {
		return sum, errors.New("postgres archive: not a KyNotes PostgreSQL archive")
	}
	sum.Schema, sum.TakenAt, sum.Rows = head.Schema, head.TakenAt, map[string]int64{}
	conn, err := db.Conn(ctx)
	if err != nil {
		return sum, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return sum, err
	}
	defer tx.Rollback()
	var schema int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&schema); err != nil {
		return sum, err
	}
	if schema != head.Schema {
		return sum, fmt.Errorf("postgres archive: archive schema %d, target schema %d; restore with the release that wrote it", head.Schema, schema)
	}
	err = conn.Raw(func(dc any) error {
		pc := pgdialect.PgxConn(dc)
		tables, err := archiveTables(ctx, pc)
		if err != nil {
			return err
		}
		if !slices.EqualFunc(tables, head.Tables, func(a, b archiveTable) bool { return a.Name == b.Name && slices.Equal(a.Columns, b.Columns) }) {
			return errors.New("postgres archive: the archive's tables differ from the target schema")
		}
		if err := clearFreshTarget(ctx, pc, tables); err != nil {
			return err
		}
		for _, t := range tables {
			if _, err := pc.Exec(ctx, `ALTER TABLE `+pgx.Identifier{t.Name}.Sanitize()+` DISABLE TRIGGER USER`); err != nil {
				return err
			}
		}
		for _, t := range tables {
			tag, err := pc.PgConn().CopyFrom(ctx, &copySection{in: in}, `COPY `+copyTarget(t)+` FROM STDIN`)
			if err != nil {
				return fmt.Errorf("postgres archive: %s: %w", t.Name, err)
			}
			sum.Rows[t.Name] = tag.RowsAffected()
		}
		var tail archiveTrailer
		if err := readArchiveLine(in, &tail); err != nil {
			return errors.New("postgres archive: missing trailer")
		}
		if _, err := in.ReadByte(); err != io.EOF {
			return errors.New("postgres archive: data after the trailer")
		}
		if len(tail.Rows) != len(sum.Rows) {
			return errors.New("postgres archive: row counts differ from the trailer")
		}
		for name, n := range sum.Rows {
			if tail.Rows[name] != n {
				return fmt.Errorf("postgres archive: %s loaded %d rows, the archive lists %d", name, n, tail.Rows[name])
			}
		}
		seqs, err := archiveSequences(ctx, pc)
		if err != nil {
			return err
		}
		if len(seqs) != len(tail.Sequences) {
			return errors.New("postgres archive: the archive's sequences differ from the target schema")
		}
		for name := range seqs {
			next, ok := tail.Sequences[name]
			if !ok {
				return errors.New("postgres archive: the archive's sequences differ from the target schema")
			}
			if _, err := pc.Exec(ctx, `SELECT setval($1::regclass, $2, false)`, pgx.Identifier{name}.Sanitize(), next); err != nil {
				return err
			}
		}
		for _, t := range tables {
			if _, err := pc.Exec(ctx, `ALTER TABLE `+pgx.Identifier{t.Name}.Sanitize()+` ENABLE TRIGGER USER`); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return sum, err
	}
	if err := fence(tx); err != nil {
		return sum, err
	}
	return sum, tx.Commit()
}

// clearFreshTarget refuses any target but a just-created one: only the rows the migrations and
// ensureOrgs write (the default theme, the single-mode record, the default org and its usage
// row). It deletes those,
// so the archive's own rows replace them.
func clearFreshTarget(ctx context.Context, pc *pgx.Conn, tables []archiveTable) error {
	seeded := map[string]string{
		"server_settings": `SELECT count(*)=count(*) FILTER (WHERE key='tenancy_mode' AND value='single' OR key='default_theme') FROM server_settings`,
		"orgs":            `SELECT count(*)=count(*) FILTER (WHERE id='` + DefaultOrgID + `') FROM orgs`,
		"org_usage":       `SELECT count(*)=count(*) FILTER (WHERE org_id='` + DefaultOrgID + `' AND bytes=0) FROM org_usage`,
	}
	for _, t := range tables {
		q, ok := seeded[t.Name]
		if !ok {
			q = `SELECT NOT EXISTS(SELECT 1 FROM ` + pgx.Identifier{t.Name}.Sanitize() + `)`
		}
		var fresh bool
		if err := pc.QueryRow(ctx, q).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return fmt.Errorf("postgres archive: the target holds data (%s); restore only into a new, empty database", t.Name)
		}
	}
	for _, q := range []string{`DELETE FROM org_usage`, `DELETE FROM server_settings`, `DELETE FROM orgs`} {
		if _, err := pc.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// archiveTables lists the schema's tables, parents before children, with their columns.
func archiveTables(ctx context.Context, pc *pgx.Conn) ([]archiveTable, error) {
	rows, err := pc.Query(ctx, `SELECT c.relname, array_agg(a.attname ORDER BY a.attnum)::text[]
FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated=''
WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='r' AND c.relname<>'schema_migrations'
GROUP BY c.relname ORDER BY c.relname`)
	if err != nil {
		return nil, err
	}
	byName := map[string]archiveTable{}
	var names []string
	for rows.Next() {
		var t archiveTable
		if err := rows.Scan(&t.Name, &t.Columns); err != nil {
			rows.Close()
			return nil, err
		}
		byName[t.Name] = t
		names = append(names, t.Name)
	}
	if rows.Close(); rows.Err() != nil {
		return nil, rows.Err()
	}
	parents := map[string][]string{}
	rows, err = pc.Query(ctx, `SELECT c.relname, p.relname FROM pg_constraint k
JOIN pg_class c ON c.oid=k.conrelid JOIN pg_class p ON p.oid=k.confrelid
WHERE k.contype='f' AND c.relnamespace=current_schema()::regnamespace ORDER BY 1,2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			rows.Close()
			return nil, err
		}
		if child == parent {
			rows.Close()
			return nil, fmt.Errorf("postgres archive: %s references itself; its rows need an order", child)
		}
		parents[child] = append(parents[child], parent)
	}
	if rows.Close(); rows.Err() != nil {
		return nil, rows.Err()
	}
	return orderTables(names, byName, parents)
}

// orderTables puts parents before children. Names and each parent list are sorted first, so
// the order depends on the schema alone, never on catalog scan order: restore compares the
// archive's table list with the target's position by position.
func orderTables(names []string, byName map[string]archiveTable, parents map[string][]string) ([]archiveTable, error) {
	names = slices.Sorted(slices.Values(names))
	var out []archiveTable
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("postgres archive: foreign keys form a cycle at %s", n)
		case 2:
			return nil
		}
		state[n] = 1
		for _, p := range slices.Sorted(slices.Values(parents[n])) {
			if err := visit(p); err != nil {
				return err
			}
		}
		state[n] = 2
		out = append(out, byName[n])
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// archiveSequences reads each sequence's next value. Sequences are not transactional, so
// this is at least the snapshot's value, which keeps them increasing after a restore.
func archiveSequences(ctx context.Context, pc *pgx.Conn) (map[string]int64, error) {
	rows, err := pc.Query(ctx, `SELECT c.relname FROM pg_class c WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='S' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, n := range names {
		var last int64
		var called bool
		if err := pc.QueryRow(ctx, `SELECT last_value, is_called FROM `+pgx.Identifier{n}.Sanitize()).Scan(&last, &called); err != nil {
			return nil, err
		}
		if called {
			last++
		}
		out[n] = last
	}
	return out, nil
}

func copyTarget(t archiveTable) string {
	cols := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		cols[i] = pgx.Identifier{c}.Sanitize()
	}
	return pgx.Identifier{t.Name}.Sanitize() + ` (` + strings.Join(cols, ",") + `)`
}

// readArchiveLine decodes one JSON line of at most 1 MiB.
func readArchiveLine(in *bufio.Reader, v any) error {
	line, err := in.ReadSlice('\n')
	if err != nil {
		return errors.New("postgres archive: truncated")
	}
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// copySection reads one table's COPY text rows, up to and without its `\.` line. COPY text
// escapes every backslash in data, so no row is that line.
type copySection struct {
	in      *bufio.Reader
	pending []byte // the rest of the last chunk that did not fit
	midLine bool
	done    bool
}

func (c *copySection) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.done {
		return 0, io.EOF
	}
	if !c.midLine {
		peek, err := c.in.Peek(3)
		if err == nil && string(peek) == "\\.\n" {
			c.in.Discard(3)
			c.done = true
			return 0, io.EOF
		}
		if err != nil { // the trailer always follows a section
			return 0, errors.New("postgres archive: truncated")
		}
	}
	chunk, err := c.in.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		c.midLine = true
	case err != nil:
		return 0, errors.New("postgres archive: truncated")
	default:
		c.midLine = false
	}
	n := copy(p, chunk)
	c.pending = append([]byte(nil), chunk[n:]...) // ReadSlice's bytes die at the next read
	return n, nil
}
