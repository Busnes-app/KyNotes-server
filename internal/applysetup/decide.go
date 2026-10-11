package applysetup

import (
	"fmt"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/sso"
)

type Status string

const (
	Created  Status = "created"
	Present  Status = "present"
	Conflict Status = "conflict"
	Invalid  Status = "invalid"
	Failed   Status = "failed"
)

// WantSSO is the stored form of the bundle's SSO section, with the same AutoProvision as
// KySignOn pairing.
func WantSSO(s SSO) sso.SSOSettings {
	return sso.SSOSettings{Enabled: true, IssuerURL: s.IssuerURL, ClientID: s.ClientID, ClientSecret: s.ClientSecret, RedirectURI: s.RedirectURI, AutoProvision: true, HMACSecret: s.HMACSecret}
}

// DecideSSO creates only when nothing is configured. AutoProvision is ignored for
// emptiness because an empty store reports it as true.
func DecideSSO(have, want sso.SSOSettings) Status {
	switch {
	case have == want:
		return Present
	case !have.Enabled && have.IssuerURL == "" && have.ClientID == "" && have.ClientSecret == "" && have.RedirectURI == "" && have.HMACSecret == "":
		return Created
	}
	return Conflict
}

// SSODiff names the differing fields, never their values.
func SSODiff(have, want sso.SSOSettings) string {
	var d []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"enabled", have.Enabled == want.Enabled},
		{"issuerUrl", have.IssuerURL == want.IssuerURL},
		{"clientId", have.ClientID == want.ClientID},
		{"clientSecret", have.ClientSecret == want.ClientSecret},
		{"redirectUri", have.RedirectURI == want.RedirectURI},
		{"autoProvision", have.AutoProvision == want.AutoProvision},
		{"hmacSecret", have.HMACSecret == want.HMACSecret},
	} {
		if !f.same {
			d = append(d, f.name)
		}
	}
	return "existing SSO settings differ in " + strings.Join(d, ", ") + "; left unchanged"
}

type Account struct{ ID, Username, Role, Status, Kind string }

type AdminAction int

const (
	NoAction AdminAction = iota
	CreateAdmin
	GrantAdmin
)

// DecideAdmin: bound is the account bound to the identity's issuer+subject; named is the
// account holding the bundle's username, looked up only when nothing is bound.
func DecideAdmin(bound, named *Account) (Status, AdminAction, string) {
	switch {
	case bound != nil && bound.Status != "active":
		return Conflict, NoAction, "the account bound to this identity is disabled; the directory owns its status"
	case bound != nil && bound.Kind != "admin":
		return Conflict, NoAction, "the account bound to this identity is an everyday account; give the administrator its own identity"
	case bound != nil && bound.Role == "admin":
		return Present, NoAction, ""
	case bound != nil:
		return Created, GrantAdmin, "granted admin to the account bound to this identity"
	case named != nil:
		return Conflict, NoAction, "username belongs to another account; bindings are never adopted by username"
	}
	return Created, CreateAdmin, ""
}

// DecideFixed checks a value the process reads from its environment at start.
func DecideFixed(running, want, env string) (Status, string) {
	if running == want {
		return Present, ""
	}
	return Conflict, fmt.Sprintf("running value is %q; set %s and restart the container", running, env)
}

func DecideInterval(stored, want int64) Status {
	switch {
	case stored < 0:
		return Created
	case stored == want:
		return Present
	}
	return Conflict
}

// DecideRecovery claims only when this instance is not paired, so a rerun never spends a
// code. A pairing without a pinned key is left for the admin UI.
func DecideRecovery(keyID, pairedURL, wantURL string) (Status, bool) {
	switch {
	case pairedURL == "":
		return Created, true
	case pairedURL != wantURL || keyID == "":
		return Conflict, false
	}
	return Present, false
}
