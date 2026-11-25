package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T) (*Store, []byte) {
	t.Helper()
	if !OnPostgresTest() {
		t.Skip("PostgreSQL archive")
	}
	src, _, _ := purgeFixture(t)
	// A value with every COPY escape, including a line that reads `\.` before escaping.
	odd := "tab\there\nline\n\\.\n\\.\r\\N é \x01 '\""
	for _, q := range []string{`INSERT INTO server_settings(key,value,updated_at) VALUES('odd',?,'t')`, `SELECT nextval('org_storage_report_seq')`, `SELECT nextval('org_storage_report_seq')`} {
		var args []any
		if strings.Contains(q, "?") {
			args = []any{odd}
		}
		if _, err := src.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := src.db.Exec(`INSERT INTO org_pool(org_id,seq,expires_at,over_since) VALUES('org_null',2,'x',NULL); INSERT INTO erased_subjects(subject,org_id,revision) VALUES('erased-fence','org_a',4)`); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	sum, err := BackupPostgres(t.Context(), src.db, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Schema == 0 || sum.TakenAt == "" || sum.Rows["blobs"] != 2 || sum.Rows["users"] != 4 {
		t.Fatalf("summary %+v", sum)
	}
	return src, buf.Bytes()
}

// tableDigests is every table's row count and content digest, schema names aside.
func tableDigests(t *testing.T, s *Store) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range catalogTables(t, s) {
		if table == "schema_migrations" {
			continue
		}
		var n int
		var digest string
		if err := s.db.QueryRow(`SELECT count(*), COALESCE(md5(string_agg(x::text, chr(10) ORDER BY x::text)),'') FROM "`+table+`" x`).Scan(&n, &digest); err != nil {
			t.Fatal(err)
		}
		out[table] = digest
	}
	return out
}

func noFence(*sql.Tx) error { return nil }

// A backup restored into a new database holds every row of every table, byte for byte, with
// sequences carried over and every trigger back on.
func TestPostgresArchiveRoundTripsEveryRow(t *testing.T) {
	src, archive := archiveFixture(t)
	dst := openFresh(t)
	sum, err := RestorePostgres(t.Context(), dst.db, bytes.NewReader(archive), noFence)
	if err != nil {
		t.Fatal(err)
	}
	want, got := tableDigests(t, src), tableDigests(t, dst)
	var empty []string
	for table, d := range want {
		if got[table] != d {
			t.Errorf("%s differs after the round trip", table)
		}
		if sum.Rows[table] == 0 {
			empty = append(empty, table)
		}
	}
	slices.Sort(empty)
	if len(got) != len(want) || strings.Join(empty, ",") != "idempotency,idempotency_keys,replica_lockouts,replica_logins,replica_rates,sso_logout_events,sso_sync_events" {
		t.Fatalf("tables %d/%d; empty %v: seed the new table in purgeFixture or archiveFixture", len(got), len(want), empty)
	}
	var odd string
	if err := dst.db.QueryRow(`SELECT value FROM server_settings WHERE key='odd'`).Scan(&odd); err != nil || !strings.Contains(odd, "\n\\.\n") {
		t.Fatalf("escaped value %q: %v", odd, err)
	}
	var next int64
	if err := dst.db.QueryRow(`SELECT nextval('org_storage_report_seq')`).Scan(&next); err != nil || next != 3 {
		t.Fatalf("sequence next=%d: %v", next, err)
	}
	var off int
	if err := dst.db.QueryRow(`SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace=current_schema()::regnamespace AND NOT g.tgisinternal AND g.tgenabled<>'O'`).Scan(&off); err != nil || off != 0 {
		t.Fatalf("%d triggers left off: %v", off, err)
	}
	// Usage triggers count again once the load is done.
	var before, after int64
	dst.db.QueryRow(`SELECT bytes FROM org_usage WHERE org_id='org_a'`).Scan(&before)
	if _, err := dst.db.Exec(`UPDATE object_versions SET ciphertext_bytes=ciphertext_bytes+5 WHERE org_id='org_a'`); err != nil {
		t.Fatal(err)
	}
	dst.db.QueryRow(`SELECT bytes FROM org_usage WHERE org_id='org_a'`).Scan(&after)
	if after != before+5 {
		t.Fatalf("usage %d -> %d: triggers are not back on", before, after)
	}
}

// A restore loads all or nothing: a damaged archive, a failing fence or a target that holds
// data leave the target as it was, and a fresh target still takes the archive afterwards.
func TestPostgresArchiveRestoreIsAllOrNothing(t *testing.T) {
	src, archive := archiveFixture(t)
	head := bytes.IndexByte(archive, '\n')
	cases := map[string]struct {
		archive []byte
		fence   func(*sql.Tx) error
	}{
		"truncated":       {archive[:len(archive)/2], noFence},
		"no trailer":      {archive[:bytes.LastIndexByte(archive[:len(archive)-1], '\n')+1], noFence},
		"extra data":      {append(append([]byte{}, archive...), "x\n"...), noFence},
		"other schema":    {append([]byte(strings.Replace(string(archive[:head]), `"schema":`, `"schema":9`, 1)), archive[head:]...), noFence},
		"failing fence":   {archive, func(*sql.Tx) error { return errors.New("fence failed") }},
		"wrong row count": {[]byte(strings.Replace(string(archive), `"blobs":2`, `"blobs":3`, 1)), noFence},
	}
	dst := openFresh(t)
	fresh := tableDigests(t, dst)
	for name, c := range cases {
		if _, err := RestorePostgres(t.Context(), dst.db, bytes.NewReader(c.archive), c.fence); err == nil {
			t.Fatalf("%s: restore succeeded", name)
		}
		for table, d := range tableDigests(t, dst) {
			if fresh[table] != d {
				t.Fatalf("%s: %s changed", name, table)
			}
		}
	}
	srcBefore := tableDigests(t, src)
	if _, err := RestorePostgres(t.Context(), src.db, bytes.NewReader(archive), noFence); err == nil || !strings.Contains(err.Error(), "holds data") {
		t.Fatalf("restore over data: %v", err)
	}
	for table, d := range tableDigests(t, src) {
		if srcBefore[table] != d {
			t.Fatalf("a refused restore changed %s", table)
		}
	}
	if _, err := RestorePostgres(t.Context(), dst.db, bytes.NewReader(archive), noFence); err != nil {
		t.Fatalf("after the failures: %v", err)
	}
}

// The archive's snapshot is one transaction: a write committed while the backup runs is
// either wholly in it or wholly out (here: blocked behind the first table, so out).
func TestPostgresArchiveIsOneSnapshot(t *testing.T) {
	src, _ := archiveFixture(t)
	w := &hookWriter{hook: func() {
		if _, err := src.db.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES('late','x','t')`); err != nil {
			t.Error(err)
		}
		if _, err := src.db.Exec(`DELETE FROM blob_containers`); err != nil {
			t.Error(err)
		}
	}}
	if _, err := BackupPostgres(context.Background(), src.db, w); err != nil {
		t.Fatal(err)
	}
	dst := openFresh(t)
	if _, err := RestorePostgres(t.Context(), dst.db, bytes.NewReader(w.buf.Bytes()), noFence); err != nil {
		t.Fatal(err)
	}
	var late, refs int
	dst.db.QueryRow(`SELECT count(*) FROM server_settings WHERE key='late'`).Scan(&late)
	dst.db.QueryRow(`SELECT count(*) FROM blob_containers`).Scan(&refs)
	if late != 0 || refs != 2 {
		t.Fatalf("late=%d refs=%d: the archive mixed two states", late, refs)
	}
}

type hookWriter struct {
	buf  bytes.Buffer
	hook func()
}

func (h *hookWriter) Write(p []byte) (int, error) {
	if h.hook != nil && h.buf.Len() > 0 { // after the header line: the snapshot is taken
		h.hook()
		h.hook = nil
	}
	return h.buf.Write(p)
}
