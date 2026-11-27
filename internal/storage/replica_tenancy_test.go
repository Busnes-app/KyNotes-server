package storage

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestReplicaOpenVerifiesImmutableTenancy(t *testing.T) {
	if !OnPostgresTest() {
		t.Skip("set KYNOTES_TEST_DATABASE_URL")
	}
	st, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var schema string
	if err := st.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	want := Tenancy{Mode: "multi", StaffOrg: "org_staff", Region: "local"}
	if s, err := OpenPostgresReplica(context.Background(), u.String(), want); err == nil {
		s.Close()
		t.Fatal("single database adopted as multi")
	}
	// Simulate the empty just-migrated target, before either mode has claimed it.
	if _, err := st.DB().Exec(`DELETE FROM server_settings WHERE key='tenancy_mode'; DELETE FROM org_usage; DELETE FROM orgs`); err != nil {
		t.Fatal(err)
	}
	replica, err := OpenPostgresReplica(context.Background(), u.String(), want)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	got, err := TenancyOf(replica.DB())
	if err != nil || got != want {
		t.Fatalf("binding: %v %v", got, err)
	}
	for _, changed := range []Tenancy{{"multi", "org_other", "local"}, {"multi", "org_staff", "other"}} {
		if s, err := OpenPostgresReplica(context.Background(), u.String(), changed); err == nil {
			s.Close()
			t.Fatal("immutable binding changed")
		}
	}
	if s, err := OpenPostgres(u.String()); err == nil {
		s.Close()
		t.Fatal("single mode opened recorded multi database")
	}
}

func TestReplicaOpenRejectsInvalidBindingBeforeConnecting(t *testing.T) {
	for _, want := range []Tenancy{{"single", "org_staff", "local"}, {"multi", "", "local"}, {"multi", DefaultOrgID, "local"}, {"multi", "org_staff", ""}} {
		if st, err := OpenPostgresReplica(context.Background(), "not-a-dsn", want); err == nil {
			st.Close()
			t.Fatal("invalid binding accepted")
		}
	}
}
