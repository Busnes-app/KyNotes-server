package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/logging"
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
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/setup", strings.NewReader(`{"username":"admin","authSecret":"`+strings.Repeat("a", 64)+`"}`)))
	check("setup", rec)

	f := newLogoutFixture(t)
	if _, err := f.db.Exec(failInsert); err != nil {
		t.Fatal(err)
	}
	check("auto-provision", roleCallback(f, "newcomer", nil, ""))
}
