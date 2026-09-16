package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/sso"
)

// A stolen admin cookie must not mint local credentials: creating a user or
// resetting a password would otherwise let the thief log in as a local user
// and take the weaker password step-up branch.
func TestCredentialRoutesRequireStepUp(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	AdminRoutes(mux, db, sso.NewStore(db))

	adminID, _ := createAdminUser(t, db) // secret is 64 x "a"
	rec := httptest.NewRecorder()
	s, err := auth.MintSession(db, rec, adminID, true, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", s.CSRF)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	create := `{"username":"mallory","authSecret":"` + strings.Repeat("c", 64) + `","loginSalt":"salt","iterations":600000,"role":"admin"}`
	reset := `{"newAuthSecret":"` + strings.Repeat("d", 64) + `","newLoginSalt":"salt","iterations":600000}`

	if rr := do("POST", "/api/v1/admin/users", create); rr.Code != 403 || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Fatalf("create without step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := do("POST", "/api/v1/admin/users/"+adminID+"/password", reset); rr.Code != 403 || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Fatalf("reset without step-up: %d %s", rr.Code, rr.Body)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='mallory'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("user created without step-up: %v %d", err, n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event IN ('admin.user.create','admin.user.password_reset')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused credential change audited as done: %v %d", err, n)
	}

	if rr := do("POST", "/api/v1/auth/step-up", `{"authSecret":"`+strings.Repeat("a", 64)+`"}`); rr.Code != 204 {
		t.Fatalf("step-up: %d %s", rr.Code, rr.Body)
	}
	if rr := do("POST", "/api/v1/admin/users", create); rr.Code != 200 {
		t.Fatalf("create after step-up: %d %s", rr.Code, rr.Body)
	}
	var victim string
	if err := db.QueryRow(`SELECT id FROM users WHERE username='mallory'`).Scan(&victim); err != nil {
		t.Fatal(err)
	}
	if rr := do("POST", "/api/v1/admin/users/"+victim+"/password", reset); rr.Code != 204 {
		t.Fatalf("reset after step-up: %d %s", rr.Code, rr.Body)
	}
}
