package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busness-app/ky-primitives/syncauth"
)

func TestSyncSignaturesAndAtomicReplay(t *testing.T) {
	db, cfg := setupTestDB(t)
	store := sso.NewStore(db)
	secret := strings.Repeat("s", 32)
	if err := store.Save(sso.SSOSettings{HMACSecret: secret, IssuerURL: "https://issuer.example"}); err != nil {
		t.Fatal(err)
	}
	newRouter := func() http.Handler { mux := http.NewServeMux(); SSORoutes(mux, db, cfg, store); return mux }
	router := newRouter()
	body, _ := json.Marshal(directoryPayload("subject-one", "alice", 1, true))
	headers, err := syncauth.Sign([]byte(secret), time.Now(), "user.created", "event-one", body)
	if err != nil {
		t.Fatal(err)
	}
	send := func(router http.Handler, path string, body []byte, h syncauth.Headers) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, bytes.NewReader(body))
		h.Apply(req)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res
	}
	for _, mode := range []string{"body", "signature", "timestamp", "type", "id", "stale", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			h := headers
			data := body
			want := 401
			switch mode {
			case "body":
				data = append(append([]byte{}, body...), byte(' '))
			case "signature":
				h.Signature = ""
			case "timestamp":
				h.Timestamp = ""
			case "type":
				h.EventType = ""
			case "id":
				h.EventID = ""
			case "stale":
				h, _ = syncauth.Sign([]byte(secret), time.Now().Add(-time.Hour), "user.created", "event-one", body)
			case "metadata":
				h, _ = syncauth.Sign([]byte(secret), time.Now(), "user.deleted", "different", body)
				want = 400
			}
			for _, path := range []string{"/api/v1/sync/events", "/api/sync/events", "/sync/events"} {
				res := send(router, path, data, h)
				if res.Code != want {
					t.Fatalf("got %d: %s", res.Code, res.Body.String())
				}
				var envelope ErrorBody
				if err := json.Unmarshal(res.Body.Bytes(), &envelope); err != nil || envelope.Error.Code == "" {
					t.Fatalf("error envelope lost: %s", res.Body.String())
				}
			}
		})
	}
	// A database failure must roll back both admission and user creation.
	if _, err := db.Exec(`CREATE TRIGGER fail_sync BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if res := send(router, "/api/v1/sync/events", body, headers); res.Code != 500 {
		t.Fatalf("want failed apply, got %d", res.Code)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sso_sync_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed event consumed: %d %v", count, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_sync`); err != nil {
		t.Fatal(err)
	}
	// Race aliases: one mutation commits; all identical deliveries acknowledge it.
	codes := make(chan int, 3)
	var wg sync.WaitGroup
	for _, path := range []string{"/api/v1/sync/events", "/api/sync/events", "/sync/events"} {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- send(router, path, body, headers).Code }()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("unexpected concurrent result %d", code)
		}
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE event='directory.apply'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent mutations: %d %v", count, err)
	}
	if res := send(newRouter(), "/sync/events", body, headers); res.Code != 200 {
		t.Fatalf("restart replay: %d", res.Code)
	}
	if err := db.QueryRow(`SELECT count(*) FROM users WHERE sso_subject='subject-one'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("users: %d %v", count, err)
	}
	// A trusted event can provision a local username, but cannot steal an existing subject binding.
	conflict := directoryPayload("other-subject", "alice", 1, true)
	conflict["eventId"], conflict["eventType"] = "conflict", "user.updated"
	if code := postSyncEvent(t, router, "/sync/events", secret, conflict); code != 500 {
		t.Fatalf("rebound subject: %d", code)
	}
	var role string
	if err := db.QueryRow(`SELECT role FROM users WHERE sso_subject='subject-one'`).Scan(&role); err != nil || role != "user" {
		t.Fatal("conflict mutated user")
	}
}
