package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func staffCredentials() string {
	raw, _ := json.Marshal(map[string]any{"authSecret": strings.Repeat("a", 64), "loginSalt": base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), "iterations": auth.LoginIterations})
	return string(raw)
}
func staffTarget(t *testing.T) *storage.Store {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("native PostgreSQL staff target")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "staff.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, q := range []string{`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO orgs(id,status,home_region) VALUES('org_staff','active','local')`, `INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t'),('region','local','t')`} {
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
	t.Setenv("KYNOTES_TENANCY", "multi")
	t.Setenv("KYNOTES_DB_DSN", dsn.String())
	t.Setenv("KYNOTES_STAFF_ORG_ID", "org_staff")
	t.Setenv("KYNOTES_REGION", "local")
	return st
}
func TestStaffUserCommandValidatesBeforeWriting(t *testing.T) {
	t.Setenv("KYNOTES_DB_DSN", "postgres://operator:fixture-secret-password@%zz/invalid")
	t.Setenv("KYNOTES_STAFF_ORG_ID", "org_staff")
	t.Setenv("KYNOTES_REGION", "local")
	for _, args := range [][]string{nil, {"add", "--username", "staff"}, {"add", "--admin", "--everyday", "--username", "staff"}, {"add", "--admin", "--username", "staff", "--password", "fixture-secret-password"}} {
		var out bytes.Buffer
		if err := staffUserCommand(t.Context(), args, strings.NewReader(staffCredentials()), &out); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "fixture-secret-password") {
			t.Fatalf("flag boundary: %v", err)
		}
	}
	for _, input := range []string{"", strings.Repeat("x", 4097), `{"password":"fixture-secret-password"}`, strings.ReplaceAll(staffCredentials(), strings.Repeat("a", 64), strings.Repeat("x", 64)), staffCredentials() + `{}`} {
		var out bytes.Buffer
		if err := staffUserCommand(t.Context(), []string{"add", "--admin", "--username", "staff"}, strings.NewReader(input), &out); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "fixture-secret-password") {
			t.Fatalf("credential boundary: %v", err)
		}
	}
	var out bytes.Buffer
	if err := staffUserCommand(t.Context(), []string{"add", "--admin", "--username", "staff"}, strings.NewReader(staffCredentials()), &out); err == nil || strings.Contains(err.Error(), "fixture-secret-password") {
		t.Fatalf("DSN boundary: %v", err)
	}
}
func TestStaffUserCommandCreatesOnlyAuditedStaffAdministrator(t *testing.T) {
	st := staffTarget(t)
	var out bytes.Buffer
	args := []string{"add", "--admin", "--username", " Staff.Operator "}
	if err := staffUserCommand(t.Context(), args, strings.NewReader(staffCredentials()), &out); err != nil {
		t.Fatal(err)
	}
	var id, kind, role, org, hash, recovery string
	var iterations, known int
	if err := st.DB().QueryRow(`SELECT id,account_kind,role,org_id,auth_secret_hash,recovery_hash,login_iterations,password_admin_known FROM users WHERE username='staff.operator'`).Scan(&id, &kind, &role, &org, &hash, &recovery, &iterations, &known); err != nil {
		t.Fatal(err)
	}
	if kind != "admin" || role != "admin" || org != "org_staff" || iterations != auth.LoginIterations || known != 1 || recovery == "" {
		t.Fatal("staff account contract changed")
	}
	if err := auth.VerifyAuthSecret(strings.Repeat("a", 64), hash); err != nil {
		t.Fatal("real password verifier refused supplied proof")
	}
	if err := auth.VerifyAuthSecret(strings.Repeat("b", 64), hash); err == nil {
		t.Fatal("wrong proof matched")
	}
	if !strings.Contains(out.String(), "recovery code:") || strings.Contains(out.String(), strings.Repeat("a", 64)) {
		t.Fatal("unexpected credential output")
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE event='admin.user.create' AND object_id=? AND org_id IS NULL AND reason_code='kind=admin,source=host'`, id).Scan(&n); err != nil || n != 1 {
		t.Fatal("staff creation not audited")
	}
	if _, err := st.DB().Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,org_id) VALUES('cnt_forbidden','workbook',?,'t','t','org_staff')`, id); err == nil {
		t.Fatal("administrator acquired ordinary content")
	}
	out.Reset()
	if err := staffUserCommand(t.Context(), args, strings.NewReader(staffCredentials()), &out); err == nil || out.Len() != 0 {
		t.Fatal("duplicate staff creation changed credentials or returned a new recovery code")
	}
}
func TestStaffUserCommandRefusesWrongTargetAndRollsBackAuditFailure(t *testing.T) {
	for _, kind := range []string{"single", "staff-org", "region", "audit", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			st := staffTarget(t)
			switch kind {
			case "single":
				if _, err := st.DB().Exec(`UPDATE server_settings SET value='single' WHERE key='tenancy_mode'`); err != nil {
					t.Fatal(err)
				}
			case "staff-org":
				t.Setenv("KYNOTES_STAFF_ORG_ID", "org_customer")
			case "region":
				t.Setenv("KYNOTES_REGION", "another-region")
			case "audit":
				if _, err := st.DB().Exec(`CREATE FUNCTION refuse_staff() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='admin.user.create' THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_staff BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION refuse_staff()`); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			if kind == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var out bytes.Buffer
			if err := staffUserCommand(ctx, []string{"add", "--admin", "--username", "staff"}, strings.NewReader(staffCredentials()), &out); err == nil || out.Len() != 0 {
				t.Fatal("failed staff creation returned credentials")
			}
			var n int
			if err := st.DB().QueryRow(`SELECT count(*) FROM users WHERE username='staff'`).Scan(&n); err != nil || n != 0 {
				t.Fatal("failed creation left an account")
			}
		})
	}
}
