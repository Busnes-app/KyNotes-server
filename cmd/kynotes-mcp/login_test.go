package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	if err := newClient(srv.URL, "alice", "pw").login(context.Background()); !errors.Is(err, errFewIterations) || len(after) != 0 {
		t.Fatalf("err=%v later calls=%v", err, after)
	}
}
