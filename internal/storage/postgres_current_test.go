package storage

import (
	"errors"
	"os"
	"testing"
)

func TestPostgresCurrentNeverMigratesRestoredSchema(t *testing.T) {
	st := requirePostgres(t)
	var schema string
	if err := st.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	dsn := withSearchPath(os.Getenv("KYNOTES_TEST_DATABASE_URL"), schema)
	current, err := OpenPostgresCurrent(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	current.Close()
	var mode string
	if err := st.DB().QueryRow(`SELECT value FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode); err != nil || mode != "multi" {
		t.Fatal("maintenance changed tenancy")
	}
	latest, err := migrationCount()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE schema_migrations SET version=? WHERE version=?`, latest+1, latest); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenPostgresCurrent(t.Context(), dsn); !errors.Is(err, ErrSchemaNewer) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("newer schema: %v", err)
	}
	if _, err := st.DB().Exec(`DELETE FROM schema_migrations WHERE version=?`, latest+1); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenPostgresCurrent(t.Context(), dsn); !errors.Is(err, ErrSchemaOlder) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("older schema: %v", err)
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=?`, latest).Scan(&n); err != nil || n != 0 {
		t.Fatal("maintenance migrated older schema")
	}
}
