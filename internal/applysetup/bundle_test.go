package applysetup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func specBundle(t *testing.T, dir string) string {
	t.Helper()
	secret := writeFile(t, dir, "oidc", "client-secret-value\n")
	hmac := writeFile(t, dir, "hmac", "hmac-secret-value")
	code := writeFile(t, dir, "pair", "123456\r\n")
	return fmt.Sprintf(`{"version":1,
 "sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecretFile":%q,"redirectUri":"https://notes.example/api/v1/auth/oidc/callback","directoryHmacSecretFile":%q},
 "admins":[{"issuer":"https://id.example","subject":"sub-owner","username":"owner-admin"}],
 "backup":{"dir":"/backups","keep":7,"depositInterval":"24h","recovery":{"url":"https://kyrecovery.example","pairingCodeFile":%q}}}`, secret, hmac, code)
}

func TestLoadReadsSecretsFromFiles(t *testing.T) {
	dir := t.TempDir()
	req, err := Load(writeFile(t, dir, "bundle.json", specBundle(t, dir)), false)
	if err != nil {
		t.Fatal(err)
	}
	if req.SSO.ClientSecret != "client-secret-value" || req.SSO.HMACSecret != "hmac-secret-value" || req.Backup.Recovery.PairingCode != "123456" || req.Admins[0].Username != "owner-admin" {
		t.Fatalf("%+v", req)
	}
}

func TestLoadRefusesHostileBundles(t *testing.T) {
	dir := t.TempDir()
	secret := writeFile(t, dir, "oidc", "client-secret-value")
	code := writeFile(t, dir, "code", "123456")
	sso := func(extra string) string {
		return `{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","redirectUri":"https://notes.example/api/v1/auth/oidc/callback",` + extra + `}}`
	}
	cases := map[string]string{
		"inline client secret":  sso(`"clientSecret":"inline","clientSecretFile":"` + secret + `"`),
		"inline hmac secret":    sso(`"hmacSecret":"inline","clientSecretFile":"` + secret + `"`),
		"inline pairing code":   `{"version":1,"backup":{"recovery":{"url":"https://kyrecovery.example","pairingCode":"123456"}}}`,
		"relative secret path":  sso(`"clientSecretFile":"oidc"`),
		"missing secret file":   sso(`"clientSecretFile":"` + filepath.Join(dir, "absent") + `"`),
		"empty secret file":     sso(`"clientSecretFile":"` + writeFile(t, dir, "empty", "\n") + `"`),
		"oversize secret file":  sso(`"clientSecretFile":"` + writeFile(t, dir, "big", strings.Repeat("s", MaxSecretBytes+1)) + `"`),
		"secret is a directory": sso(`"clientSecretFile":"` + dir + `"`),
		"http recovery url":     `{"version":1,"backup":{"recovery":{"url":"http://kyrecovery.example","pairingCodeFile":"` + code + `"}}}`,
		"unknown field":         `{"version":1,"theme":"dark"}`,
		"missing version":       `{}`,
	}
	for name, body := range cases {
		if _, err := Load(writeFile(t, dir, "bundle.json", body), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := writeFile(t, dir, "big.json", `{"version":1,"admins":[`+strings.Repeat(" ", MaxBundleBytes)+`]}`)
	if _, err := Load(big, false); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize bundle: %v", err)
	}
}

func TestLoadErrorsNeverEchoSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := writeFile(t, dir, "oidc", "client-secret-value\x01")
	path := writeFile(t, dir, "bundle.json", `{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecretFile":"`+secret+`","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}`)
	if _, err := Load(path, false); err == nil || strings.Contains(err.Error(), "client-secret-value") {
		t.Fatalf("got %v", err)
	}
}
