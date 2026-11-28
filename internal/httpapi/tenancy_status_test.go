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

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

// In multi mode an org that does not serve (suspended, disabled or in another region) is refused
// on every credential at the next request: sessions and devices answer 401 and its share links
// 404. When it serves again, devices and links work with no re-linking (spec, Lifecycle).
func TestStoppedOrgIsRefusedOnEveryCredential(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	generation := keyForTest(t, p.db, cid, pairUser)
	oid, code := p.save(t, cid, "", generation)
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
	if _, err := p.db.Exec(`UPDATE server_settings SET value='eu' WHERE key='region'; INSERT INTO server_settings(key,value,updated_at) VALUES('cell:eu','','')`); err != nil {
		t.Fatal(err)
	}
	set := func(q string) {
		t.Helper()
		if _, err := p.db.Exec(q, storage.DefaultOrgID); err != nil {
			t.Fatal(err)
		}
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
	serving, stopped := [4]int{200, 200, 200, 200}, [4]int{401, 401, 404, 404}
	set(`UPDATE orgs SET home_region='eu' WHERE id=?`)
	if got := answers(); got != serving {
		t.Fatalf("a serving org: %v", got)
	}
	for _, stop := range []string{`UPDATE orgs SET status='suspended' WHERE id=?`, `UPDATE orgs SET status='active',enabled=0 WHERE id=?`, `UPDATE orgs SET enabled=1,home_region='us' WHERE id=?`} {
		set(stop)
		if got := answers(); got != stopped {
			t.Fatalf("after %q: %v, want %v", stop, got, stopped)
		}
	}
	set(`UPDATE orgs SET status='active',enabled=1,home_region='eu' WHERE id=?`)
	if got := answers(); got != serving {
		t.Fatalf("after resuming: %v", got)
	}
	// A restore's replay gate stops every customer org until the feeds are replayed.
	set(`INSERT INTO server_settings(key,value,updated_at) SELECT '` + storage.RestoreReplayKey + `','pending',?`)
	if got := answers(); got != stopped {
		t.Fatalf("during the restore replay: %v, want %v", got, stopped)
	}
	set(`DELETE FROM server_settings WHERE key='` + storage.RestoreReplayKey + `' AND ?<>''`)
	if got := answers(); got != serving {
		t.Fatalf("after the restore replay: %v", got)
	}
}

// A stopped org's reminders wait: none is pushed, and none is lost, until it serves again.
func TestStoppedOrgsRemindersWait(t *testing.T) {
	p, _, sender := reminderServer(t)
	ps := newPushService(t)
	sender.Client = webpush.NewClient(ps.srv.Client().Transport)
	sender.Allow = func(endpoint string) bool { return strings.HasPrefix(endpoint, ps.srv.URL+"/") }
	addSubscription(t, p.db, p.id, "wps_live", ps.srv.URL+"/live")
	now := time.Now().UTC().Truncate(time.Minute)
	addReminder(t, p.db, p.id, strings.Repeat("a", 26), now)
	toMultiMode(t, p.db, "org_staff")
	for _, q := range []string{`UPDATE server_settings SET value='eu' WHERE key='region'; INSERT INTO server_settings(key,value,updated_at) VALUES('cell:eu','','')`, `UPDATE orgs SET status='suspended',home_region='eu' WHERE id='` + storage.DefaultOrgID + `'`} {
		if _, err := p.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := sender.Fire(context.Background(), p.db, now); err != nil {
		t.Fatal(err)
	}
	if ps.count("/live") != 0 || count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 1 {
		t.Fatalf("a suspended org's reminder was pushed (%v) or dropped", ps.hits)
	}
	if _, err := p.db.Exec(`UPDATE orgs SET status='active' WHERE id=?`, storage.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	if err := sender.Fire(context.Background(), p.db, now); err != nil {
		t.Fatal(err)
	}
	if ps.count("/live") != 1 {
		t.Fatalf("the resumed org's reminder was not pushed: %v", ps.hits)
	}
}

// Through the org poll: a suspension ends the org's sessions, so a device paired from an SSO
// session (bound to it, as every SSO-derived device is) must be linked again after the resume,
// while a device paired from a password session works again with no re-linking.
func TestSuspendAndResumeThroughThePoll(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	var code int
	p.deviceID, p.deviceSecret, code = p.register(t, p.mintToken(t), bytes.Repeat([]byte{1}, 32))
	if code != http.StatusOK {
		t.Fatalf("register=%d", code)
	}
	ssoDevice := *p
	ssoDevice.deviceID, ssoDevice.deviceSecret, code = p.register(t, p.mintToken(t), bytes.Repeat([]byte{2}, 32))
	if code != http.StatusOK {
		t.Fatalf("register=%d", code)
	}
	if _, err := p.db.Exec(`UPDATE devices SET sso_session_id=(SELECT id FROM sessions WHERE user_id=? LIMIT 1) WHERE id=?`, pairUser, ssoDevice.deviceID); err != nil {
		t.Fatal(err)
	}
	toMultiMode(t, p.db, "org_staff")
	revision := int64(0)
	setStatus := func(s string) {
		t.Helper()
		revision++
		list := func(context.Context, int64) ([]suitedir.Org, int64, error) {
			return []suitedir.Org{{ID: storage.DefaultOrgID, Status: s, Revision: revision, HomeRegion: "local", Enabled: true}}, revision, nil
		}
		if err := orgsync.New(p.db, list).Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	device := func(c *pairClient) int {
		code, _ := status(t, c.doDeviceOnly(t, http.MethodGet, "/api/v1/sync/pending", nil))
		return code
	}
	setStatus("active")
	if device(p) != 200 || device(&ssoDevice) != 200 {
		t.Fatal("devices refused while the org serves")
	}
	setStatus("suspended")
	if device(p) != 401 || device(&ssoDevice) != 401 {
		t.Fatal("a device served a suspended org")
	}
	setStatus("active")
	if got := device(p); got != 200 {
		t.Fatalf("the password-paired device after the resume: %d", got)
	}
	if got := device(&ssoDevice); got != 401 {
		t.Fatalf("the SSO-derived device outlived its ended session: %d", got)
	}
}
