package httpapi

import (
	"database/sql"
	"encoding/base64"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
)

// A legacy database can be large while its owner's ordinary quota still has room.
// No real instance is touched: SQLite makes the padding in this fixture's temporary directory.
func TestDatabaseHeldWritesStopBeforeCapsuleCeiling(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	if _, err := tm.owner.db.Exec(`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('shl_padding','padding',zeroblob(?),'2099-01-01','now',?)`, capsule.MaxExpandedBytes*9/10, pairUser); err != nil {
		t.Fatal(err)
	}
	if err := dbTx(tm.owner.db, func(tx *sql.Tx) error {
		return storage.ReserveCleanupAuditTx(tx, "sealed_share_link", "shl_padding", "")
	}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []struct{ path, body string }{
		{"/api/v1/objects/" + oid + "/comments", `{"bodyCiphertext":"Y3Q=","keyGeneration":2}`},
		{"/api/v1/share-links", `{"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) + `","expiresAt":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`},
		{"/api/v1/objects/" + oid + "/share-links", `{"version":1,"expiresAt":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`},
	} {
		code, out := status(t, tm.owner.do(t, http.MethodPost, req.path, []byte(req.body), true, false))
		if code != 507 || !strings.Contains(out, "storage_full") {
			t.Errorf("%s: %d %s; want 507 storage_full", req.path, code, out)
		}
	}
	var comments, links, objectLinks int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM comments),(SELECT COUNT(*) FROM sealed_share_links),(SELECT COUNT(*) FROM share_links)`).Scan(&comments, &links, &objectLinks); err != nil || comments != 0 || links != 1 || objectLinks != 0 {
		t.Fatalf("refusal leaked rows: %d %d %d %v", comments, links, objectLinks, err)
	}
	// Place the temporary fixture 384 KiB below the budget using SQLite's actual page
	// allocation (schema/index overhead varies); only test data is resized.
	budget := int64(capsule.MaxExpandedBytes * 9 / 10)
	padding := budget - (4 << 20)
	var used int64
	for range 2 {
		if _, err := tm.owner.db.Exec(`UPDATE sealed_share_links SET ciphertext=zeroblob(?) WHERE id='shl_padding'`, padding); err != nil {
			t.Fatal(err)
		}
		if err := dbTx(tm.owner.db, func(tx *sql.Tx) error { var err error; used, err = databaseBudgetBytes(tx); return err }); err != nil {
			t.Fatal(err)
		}
		padding += budget - (512 << 10) - used
	}
	if used >= budget-(400<<10) || used <= budget-(650<<10) {
		t.Fatalf("fixture needs room for one, not two 256 KiB writes: used=%d budget=%d", used, budget)
	}
	shareBody := func(n int) []byte {
		return []byte(`{"ciphertext":"` + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", n))) + `","expiresAt":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/share-links", shareBody(512<<10), true, false)); code != 507 {
		t.Fatalf("crossing write: %d %s", code, out)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='share_link.create'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("refused write audited as success: %d %v", audits, err)
	}
	// Both callers see the same old capacity; the immediate write transaction admits only one.
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, err := tm.owner.send(http.MethodPost, "/api/v1/share-links", shareBody(256<<10))
			if err != nil {
				codes <- 0
			} else {
				codes <- code
			}
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	if got[200] != 1 || got[507] != 1 {
		t.Fatalf("concurrent admission=%v", got)
	}

}

func TestCommentAuthorCanDeleteAndReleaseQuota(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	id, code := tm.editor.comment(t, oid, 2)
	if code != 200 {
		t.Fatal(code)
	}
	code, out := status(t, tm.editor.do(t, http.MethodDelete, "/api/v1/comments/"+id, nil, true, false))
	if code != 204 {
		t.Fatalf("comment delete: %d %s; want 204", code, out)
	}
	var live int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM comments WHERE id=? AND deleted_at=''`, id).Scan(&live); err != nil || live != 0 {
		t.Fatalf("live=%d %v", live, err)
	}
}

func TestCommentDeletionAuthorityAuditAndRollback(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.editor.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	outsider := tm.owner.addUser(t, "outsider")
	serverAdmin := tm.owner.addAdmin(t, "server-admin")
	comment := func() string {
		id, code := tm.editor.comment(t, oid, 2)
		if code != 200 {
			t.Fatal(code)
		}
		return id
	}
	remove := func(p *pairClient, id string, csrf bool) int {
		code, _ := status(t, p.do(t, http.MethodDelete, "/api/v1/comments/"+id, nil, csrf, false))
		return code
	}
	id := comment()
	for _, c := range []struct {
		name string
		p    *pairClient
		want int
	}{
		{"other editor", tm.viewer.pairClient, 403}, {"outsider", outsider.pairClient, 404}, {"server admin", serverAdmin.pairClient, 403},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code := remove(c.p, id, true); code != c.want {
				t.Fatalf("delete=%d want=%d", code, c.want)
			}
		})
	}
	if code := remove(tm.owner, id, false); code != 403 {
		t.Fatalf("without csrf=%d", code)
	}
	// A failed audit rolls back ciphertext removal, quota release, mentions and the sequence.
	if _, err := tm.owner.db.Exec(`INSERT INTO mentions(comment_id,mentioned_user_id) VALUES(?,?)`, id, pairUser); err != nil {
		t.Fatal(err)
	}
	var seq int64
	if err := tm.owner.db.QueryRow(`SELECT change_seq FROM containers WHERE id=?`, tm.id).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.owner.db.Exec(`CREATE TRIGGER reject_comment_audit BEFORE UPDATE ON cleanup_audit_slots WHEN OLD.kind='comment' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if code := remove(tm.owner, id, true); code != 500 {
		t.Fatalf("failed audit=%d", code)
	}
	var bytes, mentions int
	var afterSeq int64
	if err := tm.owner.db.QueryRow(`SELECT length(body_ciphertext),(SELECT COUNT(*) FROM mentions WHERE comment_id=?1),(SELECT change_seq FROM containers WHERE id=?2) FROM comments WHERE id=?1 AND deleted_at=''`, id, tm.id).Scan(&bytes, &mentions, &afterSeq); err != nil || bytes != 2 || mentions != 1 || seq != afterSeq {
		t.Fatalf("rollback=%d %d %d/%d %v", bytes, mentions, seq, afterSeq, err)
	}
	if _, err := tm.owner.db.Exec(`DROP TRIGGER reject_comment_audit`); err != nil {
		t.Fatal(err)
	}
	scope := `SELECT id FROM containers WHERE owner_user_id=?1`
	before, err := usedBytes(tm.owner.db, scope, pairUser, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*pairClient{tm.owner, tm.editor.pairClient, tm.admin.pairClient} {
		if code := remove(p, id, true); code != 204 {
			t.Fatalf("authorized deletion/retry=%d", code)
		}
	}
	after, err := usedBytes(tm.owner.db, scope, pairUser, "")
	if err != nil || before-after != 2 {
		t.Fatalf("quota release=%d %v", before-after, err)
	}
	var audits int
	if err := tm.owner.db.QueryRow(`SELECT length(body_ciphertext),(SELECT COUNT(*) FROM mentions WHERE comment_id=?1),(SELECT COUNT(*) FROM audit_history WHERE event='comment.delete' AND object_id=?1) FROM comments WHERE id=?1 AND deleted_at<>''`, id).Scan(&bytes, &mentions, &audits); err != nil || bytes != 0 || mentions != 0 || audits != 1 {
		t.Fatalf("delete=%d %d %d %v", bytes, mentions, audits, err)
	}
	id = comment()
	if code := remove(tm.admin.pairClient, id, true); code != 204 {
		t.Fatalf("notebook admin=%d", code)
	}
	// Demotion to viewer does not prevent an author removing its own comment.
	id = comment()
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET role='viewer' WHERE container_id=? AND user_id=?`, tm.id, tm.editor.id); err != nil {
		t.Fatal(err)
	}
	if code := remove(tm.editor.pairClient, id, true); code != 204 {
		t.Fatalf("viewer author=%d", code)
	}
	// Retained author identity confers no access after membership removal.
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET revoked_at='now' WHERE container_id=? AND user_id=?`, tm.id, tm.editor.id); err != nil {
		t.Fatal(err)
	}
	if code := remove(tm.editor.pairClient, id, true); code != 404 {
		t.Fatalf("removed author=%d", code)
	}
	if _, err := tm.owner.db.Exec(`UPDATE memberships SET approved=0,pending_role='editor',role='viewer' WHERE container_id=? AND user_id=?`, tm.id, tm.admin.id); err != nil {
		t.Fatal(err)
	}
	if code := remove(tm.admin.pairClient, id, true); code != 404 {
		t.Fatalf("pending admin=%d", code)
	}
}

// The diagnostic ID is normalized once, and the bounded value is the one the deletion audits.
func TestCommentDeletionAuditUsesTheBoundedReplyRequestID(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	mux := http.NewServeMux()
	CollabRoutes(mux, tm.owner.db, config.Defaults().Limits)
	_, loopback, _ := net.ParseCIDR("127.0.0.1/32")
	h := MiddlewareWithProxies(logging.New(io.Discard, "info", "json"), 1<<20, []*net.IPNet{loopback})(mux)
	for _, c := range []struct {
		name, id string
		kept     bool
	}{
		{"128 bytes", strings.Repeat("é", 64), true},
		{"129 bytes", strings.Repeat("x", 129), false},
		{"CRLF removed before length", strings.Repeat("x", 64) + "\r\n" + strings.Repeat("x", 64), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, code := tm.owner.comment(t, oid, 2)
			if code != 200 {
				t.Fatal(code)
			}
			req := httptest.NewRequest(http.MethodDelete, tm.owner.url+"/api/v1/comments/"+id, nil)
			req.RemoteAddr = "127.0.0.1:4444"
			req.Header.Set("X-Request-Id", c.id)
			for _, cookie := range tm.owner.hc.Jar.Cookies(req.URL) {
				req.AddCookie(cookie)
				if cookie.Name == "csrf_token" {
					req.Header.Set("X-CSRF-Token", cookie.Value)
				}
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 204 {
				t.Fatalf("delete=%d %s", rec.Code, rec.Body.String())
			}
			reply := rec.Header().Get("X-Request-Id")
			normalized := strings.NewReplacer("\r", "", "\n", "").Replace(c.id)
			if len(reply) > 128 || reply == "" || (c.kept && reply != normalized) || (!c.kept && (reply == normalized || ids.Validate("req", reply) != nil)) {
				t.Fatalf("reply ID=%q", reply)
			}
			var audited string
			if err := tm.owner.db.QueryRow(`SELECT request_id FROM audit_history WHERE event='comment.delete' AND object_id=?`, id).Scan(&audited); err != nil || audited != reply {
				t.Fatalf("audit=%q reply=%q %v", audited, reply, err)
			}
		})
	}
}
