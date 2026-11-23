package main

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestPostgresRestoreCommandBoundary(t *testing.T) {
	t.Setenv("KYNOTES_DB_DSN", "")
	for _, args := range [][]string{nil, {"--dsn", "fixture-private-dsn"}, {"--confirm-restored", "unexpected"}, {"--confirm-restored"}} {
		var out bytes.Buffer
		if err := preparePostgresRestoreCommand(args, &out); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "fixture-private-dsn") {
			t.Fatalf("bad boundary: %v", err)
		}
	}
	t.Setenv("KYNOTES_DB_DSN", "postgres://operator:fixture-private-password@%zz/invalid")
	if err := preparePostgresRestoreCommand([]string{"--confirm-restored"}, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "fixture-private-password") {
		t.Fatalf("DSN error: %v", err)
	}
}
func TestPostgresRestoreCommandUsesExistingTarget(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("native PostgreSQL target")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, q := range []string{`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t'),('region','local','t')`} {
		if _, err := st.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var schema string
	if err := st.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	t.Setenv("KYNOTES_DB_DSN", dsn.String())
	var out bytes.Buffer
	if err := preparePostgresRestoreCommand([]string{"--confirm-restored"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "does not enable multi startup") {
		t.Fatal("command overclaims readiness")
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE event='platform.restore_prepared'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("missing preparation audit: %d %v", n, err)
	}
}
