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
				_, _ = w.Write([]byte(`{"loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}`))
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

// A server asking for fewer iterations than new accounts use never receives a derived secret.
func TestLoginRefusesFewIterations(t *testing.T) {
	var after []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/login-params" {
			_, _ = w.Write([]byte(`{"loginSalt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":100000}`))
			return
		}
		after = append(after, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p := &client{base: srv.URL, user: "probe", password: "pw", hc: &http.Client{Timeout: 5 * time.Second}}
	if err := p.login(); err == nil || len(after) != 0 {
		t.Fatalf("err=%v later calls=%v", err, after)
	}
}
