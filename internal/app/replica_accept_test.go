package app

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func replicaMaintenanceTarget(t *testing.T) (*storage.Store, string) {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("native PostgreSQL maintenance")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, q := range []string{`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO orgs(id,status,home_region) VALUES('org_staff','active','eu')`, `INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t'),('region','eu','t')`} {
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
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	replicaEnvironment(t)
	t.Setenv("KYNOTES_DB_DSN", dsn.String())
	t.Setenv("KYNOTES_TENANCY", "multi")
	t.Setenv("KYNOTES_SERVER_BIND", "127.0.0.1:8080")
	t.Setenv("KYNOTES_SERVER_DEV_INSECURE_COOKIES", "true")
	dir := t.TempDir()
	t.Setenv("KYNOTES_DATA_DIR", dir)
	return st, filepath.Join(dir, "config.yaml")
}

func TestReplicaMaintenanceUsesFullFingerprintAndRetainedKey(t *testing.T) {
	st, path := replicaMaintenanceTarget(t)
	c, err := config.LoadReplicaMaintenance(path)
	if err != nil {
		t.Fatal(err)
	}
	c, in, err := readReplicaInputs(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.VerifyReplicaConfig(t.Context(), st.DB(), c.Secrets.ServerSaltKey, replicaFields(c, in)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYNOTES_SSO_CLIENT_SECRET", "new-private-client-secret")
	if err := AcceptReplicaConfiguration(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	c, in, err = readReplicaInputs(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.VerifyReplicaConfig(t.Context(), st.DB(), c.Secrets.ServerSaltKey, replicaFields(c, in)); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := st.DB().QueryRow(`SELECT reason_code FROM audit_events WHERE event='admin.replica_config_accepted'`).Scan(&reason); err != nil || reason != "fields=sso" {
		t.Fatalf("audit %q %v", reason, err)
	}
	t.Setenv("KYNOTES_SECRETS_SERVER_SALT_KEY", strings.Repeat("z", 32))
	if err := AcceptReplicaConfiguration(t.Context(), path); err == nil {
		t.Fatal("retained encryption key rotated")
	}
	t.Setenv("KYNOTES_SECRETS_SERVER_SALT_KEY", c.Secrets.ServerSaltKey)
	t.Setenv("KYNOTES_STAFF_ORG_ID", "org_customer")
	if err := AcceptReplicaConfiguration(t.Context(), path); err == nil {
		t.Fatal("wrong recorded target accepted")
	}
	if err := storage.VerifyReplicaConfig(t.Context(), st.DB(), c.Secrets.ServerSaltKey, replicaFields(c, in)); err != nil {
		t.Fatal("refusal changed fingerprint", err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("maintenance enabled hosted startup")
	}
}

func TestStaffBootstrapIsAuditedStaffOnlyAndConcurrentSafe(t *testing.T) {
	st, _ := replicaMaintenanceTarget(t)
	t.Setenv("BOOTSTRAP_ADMIN_USER", " Operator ")
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "staff bootstrap actual password")
	t.Setenv("BOOTSTRAP_EVERYDAY_USER", "")
	t.Setenv("BOOTSTRAP_EVERYDAY_PASS", "")
	c := config.Defaults()
	c.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	other, err := storage.OpenPostgresCurrent(t.Context(), os.Getenv("KYNOTES_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, db := range []*storage.Store{st, other} {
		wg.Go(func() { outcomes <- EnsureBootstrapAdmin(db.DB(), c) })
	}
	wg.Wait()
	close(outcomes)
	for err := range outcomes {
		if err != nil {
			t.Fatal(err)
		}
	}
	var org, kind, hash, salt string
	var n, iterations, known int
	if err := st.DB().QueryRow(`SELECT org_id,account_kind,auth_secret_hash,login_salt,login_iterations,password_admin_known FROM users WHERE username='operator'`).Scan(&org, &kind, &hash, &salt, &iterations, &known); err != nil {
		t.Fatal(err)
	}
	if org != "org_staff" || kind != "admin" || known != 1 {
		t.Fatal("bootstrap granted an everyday/customer account")
	}
	proof, err := auth.DeriveAuthSecret("staff bootstrap actual password", salt, iterations)
	if err != nil || auth.VerifyAuthSecret(proof, hash) != nil {
		t.Fatal("real password verification failed", err)
	}
	if err := auth.VerifyAuthSecret(strings.Repeat("b", 64), hash); err == nil {
		t.Fatal("wrong proof matched")
	}
	if err := st.DB().QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil || n != 1 {
		t.Fatal("multiple replicas seeded twice", n, err)
	}
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_events WHERE event='admin.user.create' AND org_id IS NULL AND reason_code='kind=admin,source=bootstrap'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("bootstrap audit", n, err)
	}
	t.Setenv("BOOTSTRAP_EVERYDAY_USER", "customer")
	if err := EnsureBootstrapAdmin(st.DB(), c); err == nil {
		t.Fatal("multi everyday bootstrap accepted")
	}
}

func TestStaffBootstrapAuditFailureAndCustomerAdminDoNotGrantStaff(t *testing.T) {
	st, _ := replicaMaintenanceTarget(t)
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "staff bootstrap actual password")
	t.Setenv("BOOTSTRAP_ADMIN_USER", "operator")
	t.Setenv("BOOTSTRAP_EVERYDAY_USER", "")
	t.Setenv("BOOTSTRAP_EVERYDAY_PASS", "")
	if _, err := st.DB().Exec(`INSERT INTO users(id,username,role,account_kind,status,created_at,updated_at) VALUES('usr_customer_admin','customer-admin','admin','admin','active','t','t')`); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if !WarnWithoutAdmin(st.DB(), logging.New(&output, "info", "json")) {
		t.Fatal("customer administrator masked missing staff")
	}
	if _, err := st.DB().Exec(`CREATE FUNCTION refuse_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='admin.user.create' THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_bootstrap BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION refuse_bootstrap()`); err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	c.Secrets.ServerSaltKey = strings.Repeat("s", 32)
	if err := EnsureBootstrapAdmin(st.DB(), c); err == nil {
		t.Fatal("unaudited bootstrap succeeded")
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM users WHERE org_id='org_staff'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed audit left administrator", n, err)
	}
}
