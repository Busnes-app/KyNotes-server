package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
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

// Q2: a sealed share link has an owner, counts toward the owner's quota, lasts at most 30 days,
// is audited, can be listed and revoked by its owner only, and GC deletes it once revoked.
func TestSealedShareLinksAreOwnedCappedChargedAndRevocable(t *testing.T) {
	tm := newTeam(t)
	body := func(expires time.Time, size int) []byte {
		return []byte(`{"ciphertext":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, size)) + `","expiresAt":"` + expires.UTC().Format(time.RFC3339) + `"}`)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/share-links", body(time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), 32), true, false)); code != http.StatusBadRequest {
		t.Fatalf("expiry in 9999=%d %s", code, out)
	}
	code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/share-links", body(time.Now().Add(7*24*time.Hour), 32), true, false))
	var link struct{ ID, Token string }
	if code != http.StatusOK || json.Unmarshal([]byte(out), &link) != nil {
		t.Fatalf("create=%d %s", code, out)
	}
	code, out = status(t, tm.owner.do(t, http.MethodGet, "/api/v1/share-links", nil, false, false))
	if code != http.StatusOK || !strings.Contains(out, link.ID) || strings.Contains(out, link.Token) {
		t.Fatalf("list=%d %s", code, out)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodGet, "/api/v1/share-links", nil, false, false)); code != http.StatusOK || strings.Contains(out, link.ID) {
		t.Fatalf("another user's list=%d %s", code, out)
	}
	if _, err := tm.owner.db.Exec(`UPDATE users SET quota_bytes=40 WHERE id=?`, pairUser); err != nil {
		t.Fatal(err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/share-links", body(time.Now().Add(time.Hour), 16), true, false)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("link over quota=%d %s", code, out)
	}
	if over, err := quotaExceeded(tm.owner.db, config.Limits{}, tm.id, "", 9); err != nil || !over {
		t.Fatalf("link bytes not charged to the owner's notebooks: %v %v", over, err)
	}
	if code, out := status(t, tm.editor.do(t, http.MethodDelete, "/api/v1/share-links/"+link.ID, nil, true, false)); code != http.StatusNotFound {
		t.Fatalf("revoke by another user=%d %s", code, out)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/share-links/"+link.ID, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("revoke=%d %s", code, out)
	}
	if code, _ := status(t, tm.owner.do(t, http.MethodGet, "/api/v1/share-links/"+link.Token, nil, false, false)); code != http.StatusNotFound {
		t.Fatalf("revoked link still served: %d", code)
	}
	var audited int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event IN ('share_link.create','share_link.revoke') AND object_id=?`, link.ID).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("audit rows=%d %v", audited, err)
	}
	if _, err := storage.RunGC(tm.owner.db, nil, time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM sealed_share_links`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("GC kept %d revoked links %v", left, err)
	}
}

// F9: an upload started while its notebook is deleted takes no session.
func TestUploadRacingANotebookDeleteIsRefused(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	del := func() {
		if _, err := tm.owner.db.Exec(`UPDATE containers SET deleted_at='now' WHERE id=?`, tm.id); err != nil {
			t.Error(err)
		}
	}
	if code, out := tm.editor.sendRacing(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/uploads", map[string]string{"Content-Type": "application/json", keySchemeHeader: keySchemeShared}, []byte(`{"declaredBytes":4,"kind":"attachment"}`), del); code != http.StatusNotFound {
		t.Fatalf("upload racing a delete=%d %s", code, out)
	}
	var sessions int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM upload_sessions WHERE container_id=?`, tm.id).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d %v", sessions, err)
	}
}

// A directory user who shares the local administrator's username never links, demotes or
// disables that account.
func TestDirectoryNeverAdoptsTheLocalAdministratorByUsername(t *testing.T) {
	db, cfg := setupTestDB(t)
	adminID, _ := createAdminUser(t, db)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{HMACSecret: secret, IssuerURL: "https://issuer.example"}); err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	SSORoutes(router, db, cfg, store)
	for i, kind := range []string{"user.updated", "user.deleted"} {
		res := sendDirectory(t, router, "/sync/events", secret, "evt-"+kind, kind, directoryPayload("subject-x", "admin", int64(i+1), kind == "user.updated"))
		if res.Code == http.StatusOK {
			t.Fatalf("%s adopted the local administrator: %s", kind, res.Body.String())
		}
	}
	var subject, role, status string
	if err := db.QueryRow(`SELECT coalesce(sso_subject,''),role,status FROM users WHERE id=?`, adminID).Scan(&subject, &role, &status); err != nil || subject != "" || role != "admin" || status != "active" {
		t.Fatalf("local administrator changed: %q %s %s %v", subject, role, status, err)
	}
}
