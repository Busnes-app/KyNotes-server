package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The probe writes notes, so it stops on an administrator account before any content call.
func TestLoginRefusesAnAdministratorAccount(t *testing.T) {
	for kind, want := range map[string]error{"admin": errAdminAccount, "user": nil} {
		var after []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/auth/login-params":
				_, _ = w.Write([]byte(`{"loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`))
			case "/api/v1/auth/login":
				_, _ = w.Write([]byte(`{"user":{"id":"usr_x","role":"admin","accountKind":"` + kind + `"}}`))
			default:
				after = append(after, r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		p := &client{base: srv.URL, user: "probe", password: "pw", hc: &http.Client{Timeout: 5 * time.Second}}
		err := p.login()
		srv.Close()
		if !errors.Is(err, want) || len(after) != 0 {
			t.Fatalf("%s: err=%v later calls=%v", kind, err, after)
		}
	}
}
