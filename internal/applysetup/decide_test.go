package applysetup

import (
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

func TestDecideSSO(t *testing.T) {
	want := WantSSO(SSO{IssuerURL: "https://id.example", ClientID: "kynotes", ClientSecret: "client-secret-value", RedirectURI: "https://notes.example/api/v1/auth/oidc/callback"})
	if !want.Enabled || !want.AutoProvision {
		t.Fatalf("%+v", want)
	}
	// sso.Store.Reload reports AutoProvision=true when nothing is stored.
	if DecideSSO(sso.SSOSettings{AutoProvision: true}, want) != Created {
		t.Fatal("empty settings must be created")
	}
	if DecideSSO(want, want) != Present {
		t.Fatal("identical settings must be present")
	}
	paired := sso.SSOSettings{Enabled: true, IssuerURL: "https://id.example", ClientID: "kynotes", AutoProvision: true, HMACSecret: "paired-hmac-value"}
	if DecideSSO(paired, want) != Conflict {
		t.Fatal("a KySignOn pairing must not be overwritten")
	}
	if DecideSSO(sso.SSOSettings{IssuerURL: "https://id.example", AutoProvision: true}, want) != Conflict {
		t.Fatal("disabled but configured settings must not be overwritten")
	}
	d := SSODiff(paired, want)
	for _, field := range []string{"clientSecret", "redirectUri", "hmacSecret"} {
		if !strings.Contains(d, field) {
			t.Errorf("diff %q lacks %s", d, field)
		}
	}
	if strings.Contains(d, "client-secret-value") || strings.Contains(d, "paired-hmac-value") || strings.Contains(d, "issuerUrl") {
		t.Fatalf("diff %q leaks values or names equal fields", d)
	}
}

func TestDecideAdmin(t *testing.T) {
	admin := &Account{ID: "usr_1", Username: "owner", Role: "admin", Status: "active"}
	user := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "active"}
	disabled := &Account{ID: "usr_1", Username: "owner", Role: "user", Status: "disabled"}
	other := &Account{ID: "usr_2", Username: "owner-admin", Role: "admin", Status: "active"}
	for _, c := range []struct {
		name         string
		bound, named *Account
		status       Status
		action       AdminAction
	}{
		{"new identity", nil, nil, Created, CreateAdmin},
		{"bound admin", admin, nil, Present, NoAction},
		{"bound user", user, nil, Created, GrantAdmin},
		{"bound disabled", disabled, nil, Conflict, NoAction},
		{"username taken", nil, other, Conflict, NoAction},
	} {
		st, act, _ := DecideAdmin(c.bound, c.named)
		if st != c.status || act != c.action {
			t.Errorf("%s: got %s/%d", c.name, st, act)
		}
	}
}

func TestDecideFixed(t *testing.T) {
	if st, _ := DecideFixed("/backups", "/backups", "KYNOTES_BACKUP_DIR"); st != Present {
		t.Fatal(st)
	}
	st, d := DecideFixed("", "/backups", "KYNOTES_BACKUP_DIR")
	if st != Conflict || !strings.Contains(d, "KYNOTES_BACKUP_DIR") {
		t.Fatal(st, d)
	}
}

func TestDecideInterval(t *testing.T) {
	for _, c := range []struct {
		stored, want int64
		status       Status
	}{{-1, 86400, Created}, {86400, 86400, Present}, {3600, 86400, Conflict}, {0, 86400, Conflict}} {
		if got := DecideInterval(c.stored, c.want); got != c.status {
			t.Errorf("%d→%d: %s", c.stored, c.want, got)
		}
	}
}

func TestDecideRecovery(t *testing.T) {
	const url = "https://kyrecovery.example"
	for _, c := range []struct {
		name                string
		keyID, paired, want string
		status              Status
		claim               bool
	}{
		{"fresh", "", "", url, Created, true},
		{"key pinned by hand", "key1", "", url, Created, true},
		{"already paired", "key1", url, url, Present, false},
		{"paired elsewhere", "key1", "https://other.example", url, Conflict, false},
		{"pairing without key", "", url, url, Conflict, false},
	} {
		st, claim := DecideRecovery(c.keyID, c.paired, c.want)
		if st != c.status || claim != c.claim {
			t.Errorf("%s: got %s claim=%t", c.name, st, claim)
		}
	}
}
