package httpapi

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// An export_only session reaches the export routes and nothing else: every other session route
// answers 403 export_only before its handler runs (spec N11, Export).
func TestExportOnlyAdmitsOnlyTheExportRoutes(t *testing.T) {
	everyday, _, _, _ := kindsServer(t)
	if _, err := everyday.db.Exec(`UPDATE sessions SET export_only=1`); err != nil {
		t.Fatal(err)
	}
	served := map[string]bool{}
	routes := servedRoutes(t)
	// Sign-out ends the session, so it is driven last.
	sort.SliceStable(routes, func(i, j int) bool {
		return !strings.HasSuffix(routes[i], "/logout") && strings.HasSuffix(routes[j], "/logout")
	})
	for _, route := range routes {
		served[route] = true
		if catchAllRoutes[route] || publicRoutes[route] || deviceRoutes[route] {
			continue
		}
		parts := strings.SplitN(route, " ", 2)
		path := pathParam.ReplaceAllString(parts[1], "x")
		var body []byte
		if parts[0] != http.MethodGet && parts[0] != http.MethodHead && parts[0] != http.MethodDelete {
			body = []byte(`{}`)
		}
		code, out := status(t, everyday.do(t, parts[0], path, body, true, false))
		refused := code == http.StatusForbidden && (strings.Contains(out, `"export_only"`) || parts[0] == http.MethodHead) // a HEAD answer has no body
		if auth.ExportRoutes[route] == refused {
			t.Errorf("%s: %d %s (export route: %v)", route, code, out, auth.ExportRoutes[route])
		}
	}
	for route := range auth.ExportRoutes {
		if !served[route] {
			t.Errorf("%s is an export route but not served", route)
		}
	}
}

// An export_only session survives its org's deletion_scheduled state and keeps working on the
// export routes; an ordinary session does not, and a suspended org admits neither.
func TestExportOnlySessionSurvives(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	var exporting string
	if err := p.db.QueryRow(`SELECT id FROM sessions WHERE user_id=?`, pairUser).Scan(&exporting); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`UPDATE sessions SET export_only=1 WHERE id=?`, exporting); err != nil {
		t.Fatal(err)
	}
	ordinary := p.secondSession(t)
	toMultiMode(t, p.db, "org_staff")
	if _, err := p.db.Exec(`UPDATE orgs SET status='deletion_scheduled' WHERE id=?`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if code, body := status(t, p.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)); code != http.StatusOK {
			t.Fatalf("export_only request %d: %d %s", i, code, body)
		}
	}
	if code, _ := status(t, ordinary.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)); code != http.StatusUnauthorized {
		t.Fatalf("an ordinary session in a deletion_scheduled org: %d", code)
	}
	if _, err := p.db.Exec(`UPDATE orgs SET status='suspended' WHERE id=?`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if code, _ := status(t, p.do(t, http.MethodGet, "/api/v1/containers", nil, false, false)); code != http.StatusUnauthorized {
		t.Fatalf("an export_only session in a suspended org: %d", code)
	}
}
