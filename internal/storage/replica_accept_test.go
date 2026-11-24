package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestReplicaAcceptKeepsBindingsKeyAndAuditsNamesOnly(t *testing.T) {
	a, b := sharedReplicas(t)
	key := strings.Repeat("k", 32)
	fields := map[string]string{"tenancy_mode": "multi", "staff_org_id": "org_staff", "region": "local", "sso": "old-private-secret"}
	if err := VerifyReplicaConfig(t.Context(), a, key, fields); err != nil {
		t.Fatal(err)
	}
	changed := map[string]string{"tenancy_mode": "multi", "staff_org_id": "org_staff", "region": "local", "sso": "new-private-secret"}
	if err := AcceptReplicaConfig(t.Context(), a, key, changed); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReplicaConfig(t.Context(), b, key, changed); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := a.QueryRow(`SELECT reason_code FROM audit_events WHERE event='admin.replica_config_accepted'`).Scan(&reason); err != nil || reason != "fields=sso" {
		t.Fatalf("accept audit %q %v", reason, err)
	}
	for _, kind := range []string{"key", "tenancy_mode", "staff_org_id", "region"} {
		next := map[string]string{}
		for name, value := range changed {
			next[name] = value
		}
		candidate := key
		if kind == "key" {
			candidate = strings.Repeat("q", 32)
		} else {
			next[kind] = "different"
		}
		if err := AcceptReplicaConfig(t.Context(), a, candidate, next); err == nil {
			t.Fatalf("accepted changed %s", kind)
		}
		if err := VerifyReplicaConfig(t.Context(), b, key, changed); err != nil {
			t.Fatal("refusal changed fingerprint")
		}
	}
	if _, err := a.Exec(`CREATE FUNCTION deny_accept() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='admin.replica_config_accepted' THEN RAISE EXCEPTION 'test audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_accept BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION deny_accept()`); err != nil {
		t.Fatal(err)
	}
	if err := AcceptReplicaConfig(t.Context(), a, key, fields); err == nil {
		t.Fatal("unaudited config acceptance succeeded")
	}
	if err := VerifyReplicaConfig(t.Context(), b, key, changed); err != nil {
		t.Fatal("failed audit changed config")
	}
}
func TestReplicaAcceptRefusesSingleModeWithoutWrites(t *testing.T) {
	st, err := openSQLite(filepath.Join(t.TempDir(), "single.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := AcceptReplicaConfig(t.Context(), st.DB(), strings.Repeat("k", 32), map[string]string{}); err == nil {
		t.Fatal("single config accepted")
	}
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM server_settings WHERE key='replica_config_fingerprint'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("single config record written")
	}
}
