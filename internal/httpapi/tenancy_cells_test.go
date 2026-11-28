package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Cells (C5): a deployment serves the orgs of every cell in KY_CELLS, and refuses an org whose
// home_region is another cell on every credential: session, paired device, sealed and page share
// links, SSO sign-in and an export_only session. Dropping a cell from the list refuses its orgs.
func TestAnOrgOfAnotherCellIsRefusedEverywhere(t *testing.T) {
	t.Run("session, device and share links", func(t *testing.T) {
		p := newPairClient(t, strings.Repeat("p", 32))
		cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
		oid, code := p.save(t, cid, "", keyForTest(t, p.db, cid, pairUser))
		if code != http.StatusOK {
			t.Fatalf("save=%d", code)
		}
		p.deviceID, p.deviceSecret, code = p.register(t, p.mintToken(t), bytes.Repeat([]byte{1}, 32))
		if code != http.StatusOK {
			t.Fatalf("register=%d", code)
		}
		expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		_, sealedBody := status(t, p.do(t, http.MethodPost, "/api/v1/share-links", []byte(`{"ciphertext":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`","expiresAt":"`+expires+`"}`), true, false))
		_, pageBody := status(t, p.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/share-links", []byte(`{"version":1,"expiresAt":"`+expires+`"}`), true, false))
		var sealed, page struct{ Token string }
		if json.Unmarshal([]byte(sealedBody), &sealed) != nil || json.Unmarshal([]byte(pageBody), &page) != nil || sealed.Token == "" || page.Token == "" {
			t.Fatalf("links: %s %s", sealedBody, pageBody)
		}
		toMultiMode(t, p.db, "org_staff")
		if _, err := p.db.Exec(`UPDATE orgs SET home_region='us-east-2' WHERE id=?`, storage.DefaultOrgID); err != nil {
			t.Fatal(err)
		}
		answers := func() [4]int {
			t.Helper()
			var out [4]int
			out[0], _ = status(t, p.do(t, http.MethodGet, "/api/v1/containers", nil, false, false))
			out[1], _ = status(t, p.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil))
			out[2], _ = status(t, p.do(t, http.MethodGet, "/api/v1/share-links/"+sealed.Token, nil, false, false))
			out[3], _ = status(t, p.do(t, http.MethodGet, "/api/v1/share-links/"+page.Token, nil, false, false))
			return out
		}
		serving, refused := [4]int{200, 200, 200, 200}, [4]int{401, 401, 404, 404}
		for _, c := range []struct {
			cells []string
			want  [4]int
		}{{[]string{"local"}, refused}, {[]string{"local", "us-east-2"}, serving}, {[]string{"us-east-2", "local"}, serving}, {[]string{"local", "us-east-3"}, refused}} {
			if err := storage.SetServedCells(context.Background(), p.db, c.cells); err != nil {
				t.Fatal(err)
			}
			if got := answers(); got != c.want {
				t.Fatalf("serving %v: %v, want %v", c.cells, got, c.want)
			}
		}
	})

	t.Run("SSO sign-in and export_only session", func(t *testing.T) {
		f := newLogoutFixture(t)
		toMultiMode(t, f.db, "org_staff")
		if _, err := f.db.Exec(`INSERT INTO orgs(id,status,home_region) VALUES('org_b','active','us-east-2'),('org_c','active','us-east-3'),('org_closing','deletion_scheduled','us-east-2')`); err != nil {
			t.Fatal(err)
		}
		if err := storage.SetServedCells(context.Background(), f.db, []string{"local", "us-east-2"}); err != nil {
			t.Fatal(err)
		}
		if res := f.signInWith("bea", map[string]any{"org_id": "org_b"}); res.Code != 302 {
			t.Fatalf("an org of a served cell: %d %s", res.Code, res.Body.String())
		}
		if res := f.signInWith("cal", map[string]any{"org_id": "org_c"}); res.Code != 403 || errorCode(t, res.Body.String()) != "org_not_active" {
			t.Fatalf("an org of another cell: %d %s", res.Code, res.Body.String())
		}
		exporter := f.signInWith("exporter", map[string]any{"org_id": "org_closing", "export_only": true})
		if exporter.Code != 302 {
			t.Fatalf("export_only in a served cell: %d %s", exporter.Code, exporter.Body.String())
		}
		cookies := exporter.Result().Cookies()
		// Served, the session reaches only export routes: 403 export_only, not 401.
		if code := f.protected(cookies); code != 403 {
			t.Fatalf("export_only session in a served cell: %d", code)
		}
		if err := storage.SetServedCells(context.Background(), f.db, []string{"local"}); err != nil {
			t.Fatal(err)
		}
		if res := f.signInWith("bea", map[string]any{"org_id": "org_b"}); res.Code != 403 || errorCode(t, res.Body.String()) != "org_not_active" {
			t.Fatalf("an org of a dropped cell signed in: %d %s", res.Code, res.Body.String())
		}
		if res := f.signInWith("exporter2", map[string]any{"org_id": "org_closing", "export_only": true}); res.Code != 403 || errorCode(t, res.Body.String()) != "org_not_active" {
			t.Fatalf("export_only sign-in in a dropped cell: %d %s", res.Code, res.Body.String())
		}
		if code := f.protected(cookies); code != 401 {
			t.Fatalf("export_only session in a dropped cell: %d", code)
		}
	})
}
