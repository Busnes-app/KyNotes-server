package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

// reminderServer is the full router with a Web Push sender, an everyday and an administrator account.
func reminderServer(t *testing.T) (everyday, admin member, sender *webpush.Sender) {
	t.Helper()
	cfg := config.Defaults()
	cfg.DataDir = t.TempDir()
	cfg.Server.DevInsecureCookies = true
	st, err := storage.Open(filepath.Join(cfg.DataDir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := webpush.LoadKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if sender, err = webpush.New(key); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, st.DB(), blobs, cfg, sender))
	t.Cleanup(func() { srv.Close(); st.Close() })
	base := &pairClient{db: st.DB(), url: srv.URL}
	return base.addUser(t, "everyday"), base.addAdmin(t, "server-admin"), sender
}

const reminderID = "0123456789abcdefghjkmnpqrs"

func minuteFromNow(d time.Duration) string {
	return time.Now().UTC().Add(d).Truncate(time.Minute).Format(time.RFC3339)
}

func atBody(at string) []byte { return []byte(`{"at":` + quote(at) + `}`) }

func TestReminderRoutesAreEverydaySessionOnlyWithCSRF(t *testing.T) {
	p, admin, sender := reminderServer(t)
	routes := []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/api/v1/push/web/key", nil},
		{http.MethodPut, "/api/v1/push/web/subscriptions", []byte(`{"endpoint":"https://fcm.googleapis.com/fcm/send/x"}`)},
		{http.MethodDelete, "/api/v1/push/web/subscriptions", []byte(`{"endpoint":"https://fcm.googleapis.com/fcm/send/x"}`)},
		{http.MethodGet, "/api/v1/reminders", nil},
		{http.MethodPut, "/api/v1/reminders/" + reminderID, atBody(minuteFromNow(time.Hour))},
		{http.MethodDelete, "/api/v1/reminders/" + reminderID, nil},
	}
	empty, _ := cookiejar.New(nil)
	anonymous := &pairClient{hc: &http.Client{Jar: empty}, url: p.url}
	for _, route := range routes {
		if code, body := status(t, admin.do(t, route.method, route.path, route.body, true, false)); code != http.StatusForbidden || errorCode(t, body) != "admin_account" {
			t.Errorf("%s %s as an administrator: %d %s", route.method, route.path, code, body)
		}
		if code, _ := status(t, anonymous.do(t, route.method, route.path, route.body, true, false)); code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %d", route.method, route.path, code)
		}
		if route.method != http.MethodGet {
			if code, body := status(t, p.do(t, route.method, route.path, route.body, false, false)); code != http.StatusForbidden || errorCode(t, body) != "csrf_failed" {
				t.Errorf("%s %s without CSRF: %d %s", route.method, route.path, code, body)
			}
		}
	}
	code, body := status(t, p.do(t, http.MethodGet, "/api/v1/push/web/key", nil, false, false))
	var key struct{ PublicKey string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &key) != nil || key.PublicKey != sender.PublicKey() || len(key.PublicKey) != 87 {
		t.Fatalf("key=%d %s", code, body)
	}
}

func TestRemindersValidateAndCap(t *testing.T) {
	p, _, _ := reminderServer(t)
	other := (&pairClient{db: p.db, url: p.url}).addUser(t, "other")
	put := func(c member, id string, body []byte) (int, string) {
		return status(t, c.do(t, http.MethodPut, "/api/v1/reminders/"+id, body, true, false))
	}
	soon := minuteFromNow(2 * time.Hour)
	for _, id := range []string{"0123456789ABCDEFGHJKMNPQRS", "0123456789abcdefghjkmnpqr", "0123456789abcdefghjkmnpqrst", "0123456789abcdefghjkmnpqru", "rmd_0123456789abcdefghjkmnp", "0123456789abcdefghjkmnpq%2F"} {
		if code, _ := put(p, id, atBody(soon)); code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Errorf("id %q: %d", id, code)
		}
	}
	future := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Minute)
	for _, at := range []string{"", "tomorrow", future.Add(30 * time.Second).Format(time.RFC3339), future.Format("2006-01-02T15:04:05.000Z"), future.In(time.FixedZone("x", 3600)).Format(time.RFC3339), future.Format("2006-01-02T15:04Z"),
		minuteFromNow(-2 * time.Hour), minuteFromNow(401 * 24 * time.Hour)} {
		if code, body := put(p, reminderID, atBody(at)); code != http.StatusBadRequest {
			t.Errorf("at %q: %d %s", at, code, body)
		}
	}
	if code, _ := put(p, reminderID, []byte(`{"at":`)); code != http.StatusBadRequest {
		t.Errorf("malformed body: %d", code)
	}
	// Recent (clock skew) and the horizon are accepted; a second PUT moves the time.
	if code, body := put(p, reminderID, atBody(minuteFromNow(-10*time.Minute))); code != http.StatusNoContent {
		t.Fatalf("recent=%d %s", code, body)
	}
	if code, body := put(p, reminderID, atBody(soon)); code != http.StatusNoContent {
		t.Fatalf("update=%d %s", code, body)
	}
	// Another account cannot touch, or learn about, this id.
	if code, body := put(other, reminderID, atBody(minuteFromNow(3*time.Hour))); code != http.StatusNotFound {
		t.Fatalf("other account's PUT=%d %s", code, body)
	}
	if code, _ := status(t, other.do(t, http.MethodDelete, "/api/v1/reminders/"+reminderID, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("other account's DELETE=%d", code)
	}
	_, body := status(t, other.do(t, http.MethodGet, "/api/v1/reminders", nil, false, false))
	if strings.TrimSpace(body) != "[]" {
		t.Fatalf("other account sees %s", body)
	}
	code, body := status(t, p.do(t, http.MethodGet, "/api/v1/reminders", nil, false, false))
	if code != http.StatusOK || strings.TrimSpace(body) != `[{"at":"`+soon+`","id":"`+reminderID+`"}]` {
		t.Fatalf("list=%d %s", code, body)
	}
	// The cap: 500 per account, an update at the cap still works, the 501st is refused.
	tx, err := p.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxReminders; i++ {
		id := strings.Repeat("a", 23) + string("0123456789abcdefghjkmnpqrstvwxyz"[i/32/32%32]) + string("0123456789abcdefghjkmnpqrstvwxyz"[i/32%32]) + string("0123456789abcdefghjkmnpqrstvwxyz"[i%32])
		if _, err := tx.Exec(`INSERT INTO reminders(id,user_id,at,created_at) VALUES(?,?,?,'now')`, id, p.id, soon); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if code, body := put(p, reminderID, atBody(minuteFromNow(5*time.Hour))); code != http.StatusNoContent {
		t.Fatalf("update at the cap=%d %s", code, body)
	}
	if code, body := put(p, strings.Repeat("z", 26), atBody(soon)); code != http.StatusConflict || errorCode(t, body) != "already_exists" {
		t.Fatalf("501st=%d %s", code, body)
	}
	if code, _ := status(t, p.do(t, http.MethodDelete, "/api/v1/reminders/"+reminderID, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("delete=%d", code)
	}
	if code, body := put(p, strings.Repeat("z", 26), atBody(soon)); code != http.StatusNoContent {
		t.Fatalf("after a delete=%d %s", code, body)
	}
	// Reminders are not audited.
	var audits int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event LIKE 'reminder%'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("reminder audits=%d %v", audits, err)
	}
}

func TestSubscriptionsRefuseAnythingButPushServices(t *testing.T) {
	p, _, _ := reminderServer(t)
	sub := func(method, endpoint string) (int, string) {
		return status(t, p.do(t, method, "/api/v1/push/web/subscriptions", []byte(`{"endpoint":`+quote(endpoint)+`,"keys":{"p256dh":"x","auth":"y"}}`), true, false))
	}
	for _, bad := range []string{"http://fcm.googleapis.com/fcm/send/x", "https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.1/x", "https://localhost/x", "https://fcm.googleapis.com.evil.com/x",
		"https://user:pw@fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x", "https://fcm.googleapis.com:443/x", "https://kynotes.example.com/api/v1/admin/users", "https://metadata.google.internal/x"} {
		if code, body := sub(http.MethodPut, bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
	var n int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM web_push_subscriptions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused endpoints stored: %d %v", n, err)
	}
	endpoint := "https://fcm.googleapis.com/fcm/send/secret-token-path"
	for range 2 {
		if code, body := sub(http.MethodPut, endpoint); code != http.StatusNoContent {
			t.Fatalf("put=%d %s", code, body)
		}
	}
	var events []string
	rows, err := p.db.Query(`SELECT event,object_id,reason_code FROM audit_events WHERE event LIKE 'push.%' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var event, object, reason string
		if err := rows.Scan(&event, &object, &reason); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(object, "wps_") || strings.Contains(object+reason, "secret") {
			t.Fatalf("audit names the endpoint: %s %s", object, reason)
		}
		events = append(events, event+" "+reason)
	}
	rows.Close()
	if !slices.Equal(events, []string{"push.subscription.add host=fcm.googleapis.com"}) {
		t.Fatalf("an idempotent PUT audited twice or wrongly: %v", events)
	}
	for i := 1; i < maxSubscriptions; i++ {
		if code, body := sub(http.MethodPut, "https://updates.push.services.mozilla.com/wpush/v2/"+strings.Repeat("x", i)); code != http.StatusNoContent {
			t.Fatalf("sub %d=%d %s", i, code, body)
		}
	}
	if code, body := sub(http.MethodPut, "https://web.push.apple.com/one-too-many"); code != http.StatusConflict || errorCode(t, body) != "already_exists" {
		t.Fatalf("11th=%d %s", code, body)
	}
	// Another account on the same browser takes the subscription over.
	other := (&pairClient{db: p.db, url: p.url}).addUser(t, "other")
	if code, body := status(t, other.do(t, http.MethodPut, "/api/v1/push/web/subscriptions", []byte(`{"endpoint":`+quote(endpoint)+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("take-over=%d %s", code, body)
	}
	var owner string
	if err := p.db.QueryRow(`SELECT user_id FROM web_push_subscriptions WHERE endpoint=?`, endpoint).Scan(&owner); err != nil || owner != other.id {
		t.Fatalf("owner=%s %v", owner, err)
	}
	// The first account's DELETE is then a no-op; the owner's removes and audits it.
	if code, _ := sub(http.MethodDelete, endpoint); code != http.StatusNoContent {
		t.Fatalf("delete=%d", code)
	}
	if code, _ := status(t, other.do(t, http.MethodDelete, "/api/v1/push/web/subscriptions", []byte(`{"endpoint":`+quote(endpoint)+`}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("owner delete=%d", code)
	}
	var removes int
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='push.subscription.remove' AND user_id=? AND reason_code='host=fcm.googleapis.com'`, other.id).Scan(&removes); err != nil || removes != 1 {
		t.Fatalf("remove audits=%d %v", removes, err)
	}
}

// The reminder and subscription tables hold an opaque id, the owner and times, and the endpoint: no
// key material (p256dh/auth are never stored), no page, task, title or text.
func TestReminderTablesHoldOnlyIDsAndTimes(t *testing.T) {
	p, _, _ := reminderServer(t)
	columns := func(table string) []string {
		rows, err := p.db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			out = append(out, name)
		}
		return out
	}
	if got := columns("reminders"); !slices.Equal(got, []string{"id", "user_id", "at", "created_at"}) {
		t.Fatalf("reminders columns %v", got)
	}
	if got := columns("web_push_subscriptions"); !slices.Equal(got, []string{"id", "user_id", "endpoint", "created_at", "last_ok_at"}) {
		t.Fatalf("web_push_subscriptions columns %v", got)
	}
	if code, body := status(t, p.do(t, http.MethodPut, "/api/v1/reminders/"+reminderID, []byte(`{"at":`+quote(minuteFromNow(time.Hour))+`,"text":"Pay rent","noteId":"obj_x"}`), true, false)); code != http.StatusNoContent {
		t.Fatalf("put=%d %s", code, body)
	}
	var dump string
	if err := p.db.QueryRow(`SELECT id||user_id||at||created_at FROM reminders`).Scan(&dump); err != nil || strings.Contains(dump, "rent") || strings.Contains(dump, "obj_") {
		t.Fatalf("stored %q %v", dump, err)
	}
}

type pushService struct {
	mu    sync.Mutex
	hits  map[string]int
	codes map[string]int
	srv   *httptest.Server
}

func newPushService(t *testing.T) *pushService {
	ps := &pushService{hits: map[string]int{}, codes: map[string]int{}}
	ps.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if len(body) != 0 || !strings.HasPrefix(r.Header.Get("Authorization"), "vapid t=") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ps.hits[r.URL.Path]++
		code := ps.codes[r.URL.Path]
		if code == 0 {
			code = http.StatusCreated
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

func (ps *pushService) count(path string) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.hits[path]
}

func addSubscription(t *testing.T, db *sql.DB, user, id, endpoint string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO web_push_subscriptions(id,user_id,endpoint,created_at) VALUES(?,?,?,'now')`, id, user, endpoint); err != nil {
		t.Fatal(err)
	}
}

func addReminder(t *testing.T, db *sql.DB, user, id string, at time.Time) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO reminders(id,user_id,at,created_at) VALUES(?,?,?,'now')`, id, user, at.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReminderPushFiresOnceAndDropsGoneSubscriptions(t *testing.T) {
	p, _, sender := reminderServer(t)
	ps := newPushService(t)
	sender.Client = webpush.NewClient(ps.srv.Client().Transport)
	sender.Allow = func(endpoint string) bool { return strings.HasPrefix(endpoint, ps.srv.URL+"/") }
	ps.codes["/gone"] = http.StatusGone
	addSubscription(t, p.db, p.id, "wps_live", ps.srv.URL+"/live")
	addSubscription(t, p.db, p.id, "wps_gone", ps.srv.URL+"/gone")
	now := time.Now().UTC().Truncate(time.Minute)
	addReminder(t, p.db, p.id, strings.Repeat("a", 26), now)
	addReminder(t, p.db, p.id, strings.Repeat("b", 26), now.Add(-time.Minute))
	addReminder(t, p.db, p.id, strings.Repeat("c", 26), now.Add(time.Hour))
	if err := sender.Fire(context.Background(), p.db, now); err != nil {
		t.Fatal(err)
	}
	// Two reminders due, one push per subscription.
	if ps.count("/live") != 1 || ps.count("/gone") != 1 {
		t.Fatalf("pushes %v", ps.hits)
	}
	if count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 1 || count(t, p.db, `SELECT COUNT(*) FROM reminders WHERE id=?`, strings.Repeat("c", 26)) != 1 {
		t.Fatal("fired reminders were not deleted, or a future one was")
	}
	if count(t, p.db, `SELECT COUNT(*) FROM web_push_subscriptions WHERE id='wps_gone'`) != 0 || count(t, p.db, `SELECT COUNT(*) FROM web_push_subscriptions WHERE id='wps_live' AND last_ok_at<>''`) != 1 {
		t.Fatal("a 410 subscription survived, or the live one was not marked")
	}
	// Firing again sends nothing: reminders are one-shot.
	if err := sender.Fire(context.Background(), p.db, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if ps.count("/live") != 1 {
		t.Fatalf("a fired reminder pushed again: %v", ps.hits)
	}
	// The future one fires at its minute.
	if err := sender.Fire(context.Background(), p.db, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ps.count("/live") != 2 || count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 0 {
		t.Fatalf("later reminder: %v", ps.hits)
	}
}

func TestReminderPushRetriesOnlyTransientFailuresForAnHour(t *testing.T) {
	p, _, sender := reminderServer(t)
	ps := newPushService(t)
	sender.Client = webpush.NewClient(ps.srv.Client().Transport)
	sender.Allow = func(endpoint string) bool { return strings.HasPrefix(endpoint, ps.srv.URL+"/") }
	ps.codes["/busy"] = http.StatusServiceUnavailable
	addSubscription(t, p.db, p.id, "wps_busy", ps.srv.URL+"/busy")
	due := time.Now().UTC().Truncate(time.Minute)
	addReminder(t, p.db, p.id, reminderID, due)
	for _, at := range []time.Time{due, due.Add(30 * time.Minute)} {
		if err := sender.Fire(context.Background(), p.db, at); err != nil {
			t.Fatal(err)
		}
		if count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 1 {
			t.Fatalf("a transiently failed reminder was dropped at %v", at)
		}
	}
	if err := sender.Fire(context.Background(), p.db, due.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ps.count("/busy") != 3 || count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 0 || count(t, p.db, `SELECT COUNT(*) FROM web_push_subscriptions`) != 1 {
		t.Fatalf("after an hour: %v", ps.hits)
	}
	// An account that is no longer active gets no push; its due reminders go.
	addReminder(t, p.db, p.id, reminderID, due)
	ps.codes["/busy"] = 0
	if _, err := p.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, p.id); err != nil {
		t.Fatal(err)
	}
	if err := sender.Fire(context.Background(), p.db, due.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ps.count("/busy") != 3 || count(t, p.db, `SELECT COUNT(*) FROM reminders`) != 0 {
		t.Fatalf("an inactive account was pushed: %v", ps.hits)
	}
	// The production guard (no override) never contacts an endpoint outside the push services, even one in the table.
	sender.Allow = nil
	if _, err := p.db.Exec(`UPDATE users SET status='active' WHERE id=?`, p.id); err != nil {
		t.Fatal(err)
	}
	addReminder(t, p.db, p.id, reminderID, due)
	if err := sender.Fire(context.Background(), p.db, due.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ps.count("/busy") != 3 {
		t.Fatalf("an endpoint outside the allowlist was contacted: %v", ps.hits)
	}
}

func TestServiceWorkerReachesEmbeddedFile(t *testing.T) {
	handler := NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true })
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
	if res.Code != http.StatusOK || !strings.Contains(res.Header().Get("Content-Type"), "javascript") || !strings.Contains(res.Body.String(), "showNotification") {
		t.Fatalf("GET /sw.js = %d %s", res.Code, res.Header().Get("Content-Type"))
	}
	if strings.Contains(res.Body.String(), "indexedDB") || strings.Contains(res.Body.String(), "caches") || strings.Contains(res.Body.String(), "fetch(") {
		t.Fatal("the service worker touches storage, caches or the network")
	}
}
