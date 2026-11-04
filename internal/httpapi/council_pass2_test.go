package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

// Q4: deleting a notebook purges its stored data and its child notebooks', so GC can reclaim
// the blobs and the owner's quota frees.
func TestDeletingANotebookReleasesItsStorage(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	tm.rotate(t, tm.child, 1)
	for _, cid := range []string{tm.id, tm.child} {
		if _, code := tm.owner.save(t, cid, "", 2); code != http.StatusOK {
			t.Fatalf("save=%d", code)
		}
	}
	var used int64
	if err := tm.owner.db.QueryRow(`SELECT COALESCE(SUM(ciphertext_bytes),0) FROM object_versions`).Scan(&used); err != nil || used == 0 {
		t.Fatalf("nothing stored: %d %v", used, err)
	}
	limits := config.Limits{UserQuotaBytes: used}
	if over, err := quotaExceeded(tm.owner.db, limits, tm.id, "", 1); err != nil || !over {
		t.Fatalf("quota before delete over=%v %v", over, err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("delete=%d %s", code, out)
	}
	var live, versions, pages int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM containers WHERE id IN (?1,?2) AND deleted_at=''),(SELECT COUNT(*) FROM object_versions),(SELECT COUNT(*) FROM objects WHERE deleted_at='')`, tm.id, tm.child).Scan(&live, &versions, &pages); err != nil {
		t.Fatal(err)
	}
	if live != 0 || versions != 0 || pages != 0 {
		t.Fatalf("after delete: %d live notebooks, %d versions, %d live pages", live, versions, pages)
	}
	if over, err := quotaExceeded(tm.owner.db, limits, tm.id, "", 1); err != nil || over {
		t.Fatalf("quota after delete over=%v %v", over, err)
	}
}

// Q1: while no account exists, /setup needs the one-time token from secrets/setup.token; setup
// deletes it, a restart keeps an unused one, and once accounts exist a leftover is removed.
func TestSetupNeedsTheOneTimeToken(t *testing.T) {
	db, cfg := setupTestDB(t)
	if err := os.Remove(SetupTokenPath(cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	token, err := EnsureSetupToken(db, cfg.DataDir)
	if err != nil || len(token) != 32 {
		t.Fatalf("token=%q %v", token, err)
	}
	if info, err := os.Stat(SetupTokenPath(cfg.DataDir)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", info, err)
	}
	if again, err := EnsureSetupToken(db, cfg.DataDir); err != nil || again != token {
		t.Fatalf("restart replaced the token: %q %v", again, err)
	}
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/setup", strings.NewReader(body)))
		return rec
	}
	plain := strings.Replace(string(setupBody("admin", "owner")), `,"setupToken":"`+testSetupToken+`"`, "", 1)
	for name, body := range map[string]string{
		"no token":    plain,
		"wrong token": strings.Replace(string(setupBody("admin", "owner")), testSetupToken, strings.Repeat("0", 32), 1),
	} {
		if rec := post(body); rec.Code != http.StatusForbidden || errorCode(t, rec.Body.String()) != "setup_token_invalid" {
			t.Fatalf("%s=%d %s", name, rec.Code, rec.Body.String())
		}
	}
	var users int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users != 0 {
		t.Fatalf("a refused setup created %d accounts %v", users, err)
	}
	if rec := post(strings.Replace(string(setupBody("admin", "owner")), testSetupToken, token, 1)); rec.Code != http.StatusOK {
		t.Fatalf("setup with the token=%d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(SetupTokenPath(cfg.DataDir)); !os.IsNotExist(err) {
		t.Fatal("setup kept its token")
	}
	if rec := post(strings.Replace(string(setupBody("admin2", "owner2")), testSetupToken, token, 1)); rec.Code != http.StatusForbidden || errorCode(t, rec.Body.String()) != "setup_completed" {
		t.Fatalf("second setup=%d %s", rec.Code, rec.Body.String())
	}
	if err := os.WriteFile(SetupTokenPath(cfg.DataDir), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := EnsureSetupToken(db, cfg.DataDir); err != nil || got != "" {
		t.Fatalf("token with accounts=%q %v", got, err)
	}
	if _, err := os.Stat(SetupTokenPath(cfg.DataDir)); !os.IsNotExist(err) {
		t.Fatal("a leftover token stayed once accounts exist")
	}
}
