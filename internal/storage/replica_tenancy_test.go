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
	if s, err := OpenPostgresReplica(context.Background(), u.String(), want, []string{"local"}); err == nil {
		s.Close()
		t.Fatal("single database adopted as multi")
	}
	// Simulate the empty just-migrated target, before either mode has claimed it.
	if _, err := st.DB().Exec(`DELETE FROM server_settings WHERE key='tenancy_mode'; DELETE FROM org_usage; DELETE FROM orgs`); err != nil {
		t.Fatal(err)
	}
	replica, err := OpenPostgresReplica(context.Background(), u.String(), want, []string{"local", "eu"})
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	got, err := TenancyOf(replica.DB())
	if err != nil || got != want {
		t.Fatalf("binding: %v %v", got, err)
	}
	// Cells may be added or reordered; the staff org's recorded cell must stay listed.
	if s, err := OpenPostgresReplica(context.Background(), u.String(), want, []string{"eu", "us-east-2", "local"}); err != nil {
		t.Fatalf("added cell refused: %v", err)
	} else {
		s.Close()
	}
	for _, changed := range []struct {
		t     Tenancy
		cells []string
	}{{Tenancy{Mode: "multi", StaffOrg: "org_other"}, []string{"local"}}, {want, []string{"eu"}}} {
		if s, err := OpenPostgresReplica(context.Background(), u.String(), changed.t, changed.cells); err == nil {
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
		cells := []string{want.Region}
		if want.Region == "" {
			cells = nil
		}
		if st, err := OpenPostgresReplica(context.Background(), "not-a-dsn", want, cells); err == nil {
			st.Close()
			t.Fatal("invalid binding accepted")
		}
	}
}

func TestReplicaOpenRefusesMismatchedTargetBeforePendingMigration(t *testing.T) {
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
	// Roll back migration 0036 so a real pending migration exists on this target.
	rollback0036 := `
		DROP TRIGGER IF EXISTS replica_presence_org_match ON replica_presence;
		DROP FUNCTION IF EXISTS replica_presence_org_match();
		DROP TRIGGER IF EXISTS reminders_release_claim ON reminders;
		DROP FUNCTION IF EXISTS reminder_release_claim();
		ALTER TABLE reminders DROP COLUMN IF EXISTS claim_token;
		ALTER TABLE reminders DROP COLUMN IF EXISTS claimed_until;
		DROP TABLE IF EXISTS replica_presence;
		DROP TABLE IF EXISTS replica_lockouts;
		DROP TABLE IF EXISTS replica_rates;
		DROP TABLE IF EXISTS replica_logins;
		DELETE FROM schema_migrations WHERE version >= 36;
	`
	if _, err := st.DB().Exec(rollback0036); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	assertUntouched := func(label string) {
		t.Helper()
		var ver int
		if err := st.DB().QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&ver); err != nil {
			t.Fatal(err)
		}
		var hasReplicaLogins bool
		if err := st.DB().QueryRow(`SELECT to_regclass('replica_logins') IS NOT NULL`).Scan(&hasReplicaLogins); err != nil {
			t.Fatal(err)
		}
		if ver != 35 || hasReplicaLogins {
			t.Fatalf("%s mutated schema before refusal: version=%d hasReplicaLogins=%v", label, ver, hasReplicaLogins)
		}
	}

	want := Tenancy{Mode: "multi", StaffOrg: "org_staff", Region: "local"}
	// Case 1: existing single-mode database with pending migration 0036.
	if s, err := OpenPostgresReplica(context.Background(), u.String(), want, []string{"local"}); err == nil {
		s.Close()
		t.Fatal("single-mode database accepted by replica open")
	}
	assertUntouched("single-mode target")

	// Case 2: existing multi-mode database with a different staff org/region and pending 0036.
	if _, err := st.DB().Exec(`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"staff_org_id": "org_other", "region": "eu"} {
		if _, err := st.DB().Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,'') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := OpenPostgresReplica(context.Background(), u.String(), want, []string{"local"}); err == nil {
		s.Close()
		t.Fatal("mismatched multi-mode database accepted by replica open")
	}
	assertUntouched("mismatched multi-mode target")

	// Case 3: matching multi-mode binding succeeds and applies pending migration 0036.
	matched := Tenancy{Mode: "multi", StaffOrg: "org_other", Region: "eu"}
	replica, err := OpenPostgresReplica(context.Background(), u.String(), matched, []string{"eu"})
	if err != nil {
		t.Fatalf("matching multi-mode target refused: %v", err)
	}
	defer replica.Close()
	var ver int
	if err := replica.DB().QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&ver); err != nil || ver < 36 {
		t.Fatalf("matching target did not migrate: ver=%d err=%v", ver, err)
	}
}
