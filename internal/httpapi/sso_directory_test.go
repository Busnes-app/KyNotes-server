package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kynotes-server/internal/auth"
	"github.com/Busness-app/kynotes-server/internal/sso"
	"github.com/Busness-app/kynotes-server/internal/storage"
)

func directoryPayload(subject, username string, version int64, active bool) map[string]any {
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "id": subject, "externalId": subject, "userName": username, "active": active, "roles": []any{}, "meta": map[string]string{"resourceType": "User", "version": fmt.Sprintf(`W/"%d"`, version)}}
}
func sendDirectory(t *testing.T, router http.Handler, path, secret, id, kind string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	signSync(t, req, secret, id, kind, body)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	return res
}

func TestDirectoryVersionsReadbackAndRestart(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{HMACSecret: secret, IssuerURL: "https://issuer.example"}); err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	SSORoutes(router, db, cfg, store)
	send := func(id, kind string, payload any, want int) {
		t.Helper()
		res := sendDirectory(t, router, "/sync/events", secret, id, kind, payload)
		if res.Code != want {
			t.Fatalf("%s: %d %s", id, res.Code, res.Body.String())
		}
	}
	active := directoryPayload("subject", "alice", 1, true)
	send("create", "user.created", active, 200)
	disabled := directoryPayload("subject", "", 3, false)
	send("delete", "user.deleted", disabled, 200)
	send("same", "user.deleted", disabled, 200)
	send("create", "user.created", active, 422)
	send("stale-new-id", "user.created", directoryPayload("subject", "alice", 2, true), 422)
	send("conflicting-version", "user.updated", directoryPayload("subject", "alice", 3, true), 422)
	send("delete", "user.updated", directoryPayload("subject", "alice", 4, true), 422)
	send("legacy", "user.updated", map[string]any{"eventId": "legacy", "eventType": "user.updated", "user": map[string]any{"id": "subject", "username": "alice", "status": "active"}}, 400)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='directory.apply'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("mutations=%d %v", n, err)
	}
	// Neither a local status edit nor OIDC auto-provisioning can override a tombstone.
	if _, err := db.Exec(`UPDATE users SET status='active' WHERE username='alice'`); err == nil {
		t.Fatal("local edit bypassed directory denial")
	}
	if _, err := db.Exec(`DELETE FROM users WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	path := cfg.DataDir + "/kynotes_test.db"
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	router = http.NewServeMux()
	SSORoutes(router, reopened.DB(), cfg, sso.NewStore(reopened.DB()))
	if _, err := db.Exec(`DELETE FROM sso_sync_events`); err != nil {
		t.Fatal(err)
	}
	send("after-restart", "user.created", active, 422)
	send("same-after-restart", "user.deleted", disabled, 200)
	read := func(kind string, payload any, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := sendDirectory(t, router, "/api/v1/sync/readback", secret, "read", kind, payload)
		if r.Code != want {
			t.Fatalf("readback %d %s", r.Code, r.Body.String())
		}
		return r
	}
	res := read("user.readback", map[string]string{"subject": "subject"}, 200)
	var state struct {
		Present, Active bool
		Version         string
	}
	if json.Unmarshal(res.Body.Bytes(), &state) != nil || state.Present || state.Active || state.Version != `W/"3"` {
		t.Fatalf("wrong observation %s", res.Body.String())
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable readback")
	}
	read("user.deleted", disabled, 400)
	send("purpose", "user.readback", map[string]string{"subject": "subject"}, 400)
	read("user.readback", map[string]string{"subject": "unknown"}, 200)
	send("fresh", "user.created", directoryPayload("subject", "alice", 4, true), 200)
}

func TestDirectoryDisablePreservesDataAndRevokesSessionDeviceCredentials(t *testing.T) {
	f := newLogoutFixture(t)
	settings := f.settings.Load()
	settings.HMACSecret = strings.Repeat("s", 32)
	if err := f.settings.Save(settings); err != nil {
		t.Fatal(err)
	}
	cookies := f.login("alice", "sid-a")
	ShareLinkRoutes(f.router.(*http.ServeMux), f.db, nil)
	sealed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	shareBody, _ := json.Marshal(map[string]string{"ciphertext": sealed, "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	shared := f.send(withCookies(httptest.NewRequest("POST", "/api/v1/share-links", bytes.NewReader(shareBody)), cookies))
	var link struct{ Token string }
	if shared.Code != 200 || json.Unmarshal(shared.Body.Bytes(), &link) != nil || link.Token == "" {
		t.Fatalf("create share: %d %s", shared.Code, shared.Body.String())
	}

	other := f.login("bob", "sid-b")
	var uid string
	if err := f.db.QueryRow(`SELECT id FROM users WHERE username='alice'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	local := httptest.NewRecorder()
	if _, err := auth.MintSession(f.db, local, uid, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	pending := f.pairing(cookies)
	registered := f.register(f.pairing(local.Result().Cookies()))
	if registered.Code != 200 {
		t.Fatalf("register %d %s", registered.Code, registered.Body.String())
	}
	var device struct {
		DeviceID string `json:"deviceId"`
	}
	if json.Unmarshal(registered.Body.Bytes(), &device) != nil || device.DeviceID == "" {
		t.Fatalf("device %s", registered.Body.String())
	}
	for _, q := range []string{
		`INSERT INTO containers(id,kind,owner_user_id,meta_ciphertext,created_at,updated_at) VALUES('cipher-container','workbook',?,x'010203','now','now')`,
		`INSERT INTO key_envelopes(id,container_id,device_id,key_generation,alg,envelope,created_at) VALUES('cipher-key','cipher-container',?,1,'fixture',x'040506','now')`,
	} {
		arg := uid
		if strings.Contains(q, "key_envelopes") {
			arg = device.DeviceID
		}
		if _, err := f.db.Exec(q, arg); err != nil {
			t.Fatal(err)
		}
	}
	send := func(id string, version int64, active bool, want int) {
		t.Helper()
		res := sendDirectory(t, f.router, "/sync/events", settings.HMACSecret, id, "user.updated", directoryPayload("alice", "alice", version, active))
		if res.Code != want {
			t.Fatalf("event %d %s", res.Code, res.Body.String())
		}
	}
	// Audit failure must also roll back status, credential revocation, revision and replay.
	if _, err := f.db.Exec(`CREATE TRIGGER fail_directory_audit BEFORE INSERT ON audit_events WHEN NEW.event='directory.apply' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	send("disable", 1, false, 500)
	if f.protected(cookies) != 204 || f.protected(local.Result().Cookies()) != 204 {
		t.Fatal("failed transaction revoked credentials")
	}
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM sso_directory_state`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed transaction advanced revision %d %v", n, err)
	}
	if _, err := f.db.Exec(`DROP TRIGGER fail_directory_audit`); err != nil {
		t.Fatal(err)
	}
	oldCallback := f.beginLogin("alice", "pending-before-disable", time.Now().Add(-time.Second))
	send("disable", 1, false, 200)
	// Share links are independent bearer access to ciphertext, not account sessions.
	if res := f.send(httptest.NewRequest("GET", "/api/v1/share-links/"+link.Token, nil)); res.Code != 200 {
		t.Fatalf("share link after deactivation: %d %s", res.Code, res.Body.String())
	}

	if f.protected(cookies) == 204 || f.protected(local.Result().Cookies()) == 204 || f.protected(other) != 204 {
		t.Fatal("disable scope wrong")
	}
	if f.register(pending).Code == 200 {
		t.Fatal("pending pairing survived disable")
	}
	if res := f.send(f.beginLogin("alice", "disabled", time.Now())); res.Code == 302 {
		t.Fatal("disabled login succeeded")
	}
	send("enable", 2, true, 200)
	var subject, reason string
	if err := f.db.QueryRow(`SELECT object_id,reason_code FROM audit_events WHERE event='directory.apply' ORDER BY rowid LIMIT 1`).Scan(&subject, &reason); err != nil || subject != "alice" || reason != "revision=1,active=false,event=disable" {
		t.Fatalf("deactivation attribution lost after re-enable: subject=%q reason=%q err=%v", subject, reason, err)
	}

	if res := f.send(oldCallback); res.Code != 403 {
		t.Fatalf("reenable revived old callback: %d %s", res.Code, res.Body.String())
	}
	if f.protected(cookies) == 204 || f.protected(local.Result().Cookies()) == 204 {
		t.Fatal("reenable revived sessions")
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM devices WHERE user_id=? AND revoked_at=''`, uid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("device revived %d %v", n, err)
	}
	for _, q := range []string{`SELECT meta_ciphertext FROM containers WHERE id='cipher-container'`, `SELECT envelope FROM key_envelopes WHERE id='cipher-key'`} {
		var data []byte
		if err := f.db.QueryRow(q).Scan(&data); err != nil || len(data) != 3 {
			t.Fatalf("ciphertext lost %x %v", data, err)
		}
	}
	fresh := f.send(f.beginLogin("alice", "fresh", time.Now().Add(time.Second)))
	if fresh.Code != 302 || f.protected(fresh.Result().Cookies()) != 204 {
		t.Fatal("fresh login denied")
	}
}

func TestDirectoryRejectsMalformedAndChangedConfiguration(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{HMACSecret: secret, IssuerURL: "https://issuer.example"}); err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	SSORoutes(router, db, cfg, store)
	for _, mode := range []string{"schema", "id", "externalId", "active", "version", "overflow", "zero", "username", "type", "delete"} {
		t.Run(mode, func(t *testing.T) {
			body := directoryPayload("subject", "alice", 1, true)
			kind := "user.updated"
			switch mode {
			case "schema":
				body["schemas"] = []string{"wrong"}
			case "id":
				body["id"] = ""
			case "externalId":
				body["externalId"] = "someone-else"
			case "active":
				delete(body, "active")
			case "version":
				body["meta"] = map[string]string{"version": "1"}
			case "overflow":
				body["meta"] = map[string]string{"version": `W/"9223372036854775808"`}
			case "zero":
				body["meta"] = map[string]string{"version": `W/"0"`}
			case "username":
				body["userName"] = ""
			case "type":
				kind = "directory.resync"
			case "delete":
				kind = "user.deleted"
			}
			if res := sendDirectory(t, router, "/sync/events", secret, mode, kind, body); res.Code != 400 {
				t.Fatalf("got %d %s", res.Code, res.Body.String())
			}
		})
	}
	// Unknown inactive users have a fence without a user row; a callback cannot recreate them.
	res := sendDirectory(t, router, "/sync/events", secret, "unknown-disable", "user.deleted", directoryPayload("unknown", "", 1, false))
	if res.Code != 200 {
		t.Fatalf("unknown delete: %d %s", res.Code, res.Body.String())
	}
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,sso_issuer,sso_subject) VALUES('attempt','unknown','hash','salt',1,'now','now','https://issuer.example','unknown')`); err == nil {
		t.Fatal("auto-provision bypassed unknown disabled subject")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("unexpected users %d %v", n, err)
	}
	if _, err := db.Exec(`UPDATE server_settings SET value=? WHERE key='sso_hmac_secret'`, strings.Repeat("x", 32)); err != nil {
		t.Fatal(err)
	}
	res = sendDirectory(t, router, "/sync/events", secret, "old-settings", "user.created", directoryPayload("subject", "alice", 1, true))
	if res.Code != 422 {
		t.Fatalf("stale cached settings applied: %d", res.Code)
	}
	if _, err := db.Exec(`ALTER TABLE server_settings RENAME TO server_settings_missing`); err != nil {
		t.Fatal(err)
	}
	res = sendDirectory(t, router, "/sync/events", secret, "storage-failure", "user.updated", directoryPayload("subject", "alice", 2, false))
	if res.Code != 500 {
		t.Fatalf("configuration storage failure: %d %s", res.Code, res.Body.String())
	}

}

func TestDirectoryReadbackAuthenticationAndAudit(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{IssuerURL: "https://issuer.example", HMACSecret: secret}); err != nil {
		t.Fatal(err)
	}
	router := http.NewServeMux()
	SSORoutes(router, db, cfg, store)
	body := []byte(`{"subject":"alice"}`)
	for _, mode := range []string{"unsigned", "tampered"} {
		req := httptest.NewRequest("POST", "/api/v1/sync/readback", bytes.NewReader(body))
		if mode == "tampered" {
			signSync(t, req, secret, "read", "user.readback", []byte(`{"subject":"bob"}`))
		}
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != 401 {
			t.Fatalf("%s readback=%d", mode, res.Code)
		}
	}

	success := sendDirectory(t, router, "/api/v1/sync/readback", secret, "probe-event", "user.readback", map[string]string{"subject": "alice"})
	if success.Code != 200 {
		t.Fatalf("readback: %d %s", success.Code, success.Body.String())
	}
	var subject, eventID string
	if err := db.QueryRow(`SELECT object_id,reason_code FROM audit_events WHERE event='directory.readback'`).Scan(&subject, &eventID); err != nil || subject != "alice" || eventID != "probe-event" {
		t.Fatalf("unidentifiable readback: %q %q %v", subject, eventID, err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_readback_audit BEFORE INSERT ON audit_events WHEN NEW.event='directory.readback' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	res := sendDirectory(t, router, "/api/v1/sync/readback", secret, "read", "user.readback", map[string]string{"subject": "alice"})
	if res.Code != 500 || strings.Contains(res.Body.String(), `"present"`) {
		t.Fatalf("unaudited observation %d %s", res.Code, res.Body.String())
	}
}
