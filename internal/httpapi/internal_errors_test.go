package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

// A database error reaches the server log, never the client: setup and SSO auto-provision.
func TestDatabaseErrorsNeverReachTheClient(t *testing.T) {
	var logged bytes.Buffer
	old := errorLog
	errorLog = logging.New(&logged, "info", "json")
	t.Cleanup(func() { errorLog = old })
	const detail = "db-detail-7f3a"
	check := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := rec.Body.String()
		if rec.Code != http.StatusInternalServerError || errorCode(t, body) != "internal" || strings.Contains(body, detail) || strings.Contains(body, "constraint") {
			t.Fatalf("%s: %d %s", name, rec.Code, body)
		}
		if !strings.Contains(logged.String(), detail) {
			t.Fatalf("%s: detail not logged: %s", name, logged.String())
		}
		logged.Reset()
	}
	failInsert := `CREATE TRIGGER fail_user_insert BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT,'` + detail + `'); END`

	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	if _, err := db.Exec(failInsert); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/setup", bytes.NewReader(setupBody("admin", "owner"))))
	check("setup", rec)

	f := newLogoutFixture(t)
	if _, err := f.db.Exec(failInsert); err != nil {
		t.Fatal(err)
	}
	check("auto-provision", roleCallback(f, "newcomer", nil, ""))
}

// An unreachable identity provider answers a fixed message on the public login route; the dial error
// with its host goes to the server log.
func TestProviderErrorsNeverReachTheClient(t *testing.T) {
	var logged bytes.Buffer
	old := errorLog
	errorLog = logging.New(&logged, "info", "json")
	t.Cleanup(func() { errorLog = old })
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	dead.Close()
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	if err := store.Save(sso.SSOSettings{Enabled: true, IssuerURL: dead.URL, ClientID: "kynotes"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	SSORoutes(mux, db, cfg, store)
	host := strings.TrimPrefix(dead.URL, "https://")
	for _, path := range []string{"/api/v1/auth/oidc/login", "/auth/oidc/login"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if body := rec.Body.String(); rec.Code != http.StatusBadGateway || !strings.Contains(body, `"identity provider unreachable"`) || strings.Contains(body, host) {
			t.Fatalf("%s: %d %s", path, rec.Code, body)
		}
	}
	if !strings.Contains(logged.String(), host) {
		t.Fatalf("dial error not logged: %s", logged.String())
	}
}

func TestMergeSSOSecretsKeepsOnlyForTheSameTarget(t *testing.T) {
	cur := sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "k", ClientSecret: "cs", HMACSecret: "hs"}
	for _, tc := range []struct {
		name                string
		in                  sso.SSOSettings
		clearC, clearH      bool
		wantC, wantH, wantP string
	}{
		{"kept", sso.SSOSettings{IssuerURL: "https://a.example/", ClientID: "k"}, false, false, "cs", "hs", ""},
		{"replaced", sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "k", ClientSecret: "n1", HMACSecret: "n2"}, false, false, "n1", "n2", ""},
		{"cleared", sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "k"}, true, true, "", "", ""},
		{"client changed", sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "x"}, false, false, "", "", "client secret"},
		{"client changed, hmac kept", sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "x"}, true, false, "", "hs", ""},
		{"issuer changed", sso.SSOSettings{IssuerURL: "https://b.example", ClientID: "k", ClientSecret: "n1"}, false, false, "", "", "directory secret"},
		{"both", sso.SSOSettings{IssuerURL: "https://a.example", ClientID: "k", ClientSecret: "n1"}, true, false, "", "", "not both"},
	} {
		got, problem := mergeSSOSecrets(tc.in, cur, tc.clearC, tc.clearH)
		if tc.wantP != "" {
			if !strings.Contains(problem, tc.wantP) {
				t.Errorf("%s: problem %q", tc.name, problem)
			}
			continue
		}
		if problem != "" || got.ClientSecret != tc.wantC || got.HMACSecret != tc.wantH {
			t.Errorf("%s: %q %q %q", tc.name, got.ClientSecret, got.HMACSecret, problem)
		}
	}
}
