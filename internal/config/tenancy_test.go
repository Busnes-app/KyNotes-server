package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Multi-tenant mode is refused until it can run, so asking for it never serves single-tenant.
func TestTenancyEnvRefusesWhatThisReleaseCannotRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nserver:\n  bind: 127.0.0.1:8080\n  dev_insecure_cookies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		env     map[string]string
		refusal string
	}{
		{map[string]string{}, ""},
		{map[string]string{"KYNOTES_TENANCY": "single"}, ""},
		{map[string]string{"KYNOTES_TENANCY": "multi"}, "KYNOTES_TENANCY: multi is not available"},
		{map[string]string{"KYNOTES_TENANCY": "Multi"}, "KYNOTES_TENANCY: must be single or multi"},
		{map[string]string{"KYNOTES_STAFF_ORG_ID": "staff"}, "KYNOTES_STAFF_ORG_ID: set only in multi-tenant mode"},
		{map[string]string{"KYNOTES_TENANCY": "single", "KYNOTES_REGION": "eu"}, "KYNOTES_REGION: set only in multi-tenant mode"},
	} {
		for _, name := range []string{"KYNOTES_TENANCY", "KYNOTES_STAFF_ORG_ID", "KYNOTES_REGION"} {
			t.Setenv(name, tc.env[name])
		}
		_, err := Load(path)
		if tc.refusal == "" && err != nil || tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), tc.refusal)) {
			t.Errorf("%v: %v, want %q", tc.env, err, tc.refusal)
		}
		if _, err := DataDir(path); (err == nil) != (tc.refusal == "") {
			t.Errorf("%v: DataDir=%v", tc.env, err)
		}
	}
}
