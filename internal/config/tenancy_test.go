package config

import (
	"os"
	"path/filepath"
	"strconv"
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
	wantMultiNoIssuer := "KYNOTES_TENANCY: multi is not available"
	if multiTenantBuild {
		wantMultiNoIssuer = "under .test"
	}
	for _, tc := range []struct {
		env     map[string]string
		refusal string
	}{
		{map[string]string{}, ""},
		{map[string]string{"KYNOTES_TENANCY": "single"}, ""},
		{map[string]string{"KYNOTES_TENANCY": "multi"}, wantMultiNoIssuer},
		{map[string]string{"KYNOTES_TENANCY": "Multi"}, "KYNOTES_TENANCY: must be single or multi"},
		{map[string]string{"KYNOTES_STAFF_ORG_ID": "staff"}, "KYNOTES_STAFF_ORG_ID: set only in multi-tenant mode"},
		{map[string]string{"KYNOTES_TENANCY": "single", "KYNOTES_REGION": "eu"}, "KYNOTES_REGION: set only in multi-tenant mode"},
		{map[string]string{"KY_CELLS": "us-east-2"}, "KY_CELLS: set only in multi-tenant mode"},
		{map[string]string{"KYNOTES_DB_DSN": "postgres://db/kynotes"}, "KYNOTES_DB_DSN: set only in multi-tenant mode"},
		{map[string]string{"KYNOTES_SSO_ISSUER": "https://id.example"}, "KYNOTES_SSO_ISSUER: set only in multi-tenant mode"},
		{map[string]string{"KYNOTES_SSO_HMAC_SECRET": "x"}, "KYNOTES_SSO_HMAC_SECRET: set only in multi-tenant mode"},
	} {
		for _, name := range []string{"KYNOTES_TENANCY", "KYNOTES_STAFF_ORG_ID", "KY_CELLS", "KYNOTES_REGION", "KYNOTES_DB_DSN", "KYNOTES_SSO_ISSUER", "KYNOTES_SSO_HMAC_SECRET"} {
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

// KY_CELLS (Cells, C1): comma-separated home-region slugs, each once, at most 32. KYNOTES_REGION
// still names one cell; both at once is refused.
func TestCellsReadsTheServedCells(t *testing.T) {
	many := make([]string, MaxCells+1)
	for i := range many {
		many[i] = "c" + strconv.Itoa(i)
	}
	for _, tc := range []struct {
		cells, region string
		want          string // joined with ",", or "!" + part of the refusal
	}{
		{" us-east-2 , us-east-3 ", "", "us-east-2,us-east-3"},
		{"", "e2e-1", "e2e-1"},
		{strings.Join(many[:MaxCells], ","), "", strings.Join(many[:MaxCells], ",")},
		{"", "", "!KY_CELLS is required"},
		{"us-east-2", "us-east-2", "!set only KY_CELLS"},
		{"us-east-2,us-east-2", "", "!listed twice"},
		{"us-east-2,", "", "!not a home region slug"},
		{"US-East", "", "!not a home region slug"},
		{"../x", "", "!not a home region slug"},
		{"a", "", "!not a home region slug"},
		{"", "eu/1", "!not a home region slug"},
		{strings.Join(many, ","), "", "!at most 32"},
	} {
		t.Setenv("KY_CELLS", tc.cells)
		t.Setenv("KYNOTES_REGION", tc.region)
		got, err := Cells()
		if strings.HasPrefix(tc.want, "!") {
			if err == nil || !strings.Contains(err.Error(), tc.want[1:]) {
				t.Errorf("%q %q: %v %v, want %s", tc.cells, tc.region, got, err, tc.want)
			}
		} else if err != nil || strings.Join(got, ",") != tc.want {
			t.Errorf("%q %q: %v %v, want %s", tc.cells, tc.region, got, err, tc.want)
		}
	}
}
