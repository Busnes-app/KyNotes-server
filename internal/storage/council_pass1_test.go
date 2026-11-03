package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

// An older release refuses a database a newer one migrated, instead of running on it.
func TestOpenRefusesANewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(9999,'later')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = Open(path); !errors.Is(err, ErrSchemaNewer) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("open newer schema: %v, want ErrSchemaNewer", err)
	}
}
