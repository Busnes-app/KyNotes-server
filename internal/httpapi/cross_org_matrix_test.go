package httpapi

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

// Routes with no request-chosen ID the cross-org matrix could try, each with its reason. A new
// route fails TestEveryRouteIsInTheCrossOrgMatrix until it is a matrix row or listed here.
var crossOrgExempt = map[string]string{
	"POST /api/v1/me/identity/pq-upgrade": "loads the authenticated user identity only; foreign device ID is a compare-and-swap mismatch (TestPQUpgrade)",
	"GET /api/v1/share-links/{token}":     "public: the token is the credential and serves ciphertext only",
	// Another account's reminder ID answers 404 where an unused one is created: an existence
	// oracle, across orgs as across users today. Using it needs the other account's ID, an HMAC
	// under a key only that account's browser holds, which the server never shows anyone else.
	// Closing it means keying reminders by (user_id, id); spec, Residual risks.
	"PUT /api/v1/reminders/{id}": "an HMAC ID under the caller's own key (see the comment above)",
}

// matrixBodies are valid bodies for the routes that would refuse {} before reaching their
// authorization, so the matrix tests the authorization and not the body check.
var matrixBodies = map[string]string{
	"POST /api/v1/me/link-requests/{id}/claim":   `{"approverKey":"` + base64.StdEncoding.EncodeToString(make([]byte, teamkeys.PQPublicBytes)) + `"}`,
	"POST /api/v1/me/link-requests/{id}/reveal":  `{"newcomerKey":"` + base64.StdEncoding.EncodeToString(make([]byte, teamkeys.PQPublicBytes)) + `"}`,
	"POST /api/v1/me/link-requests/{id}/approve": `{"bundle":"` + base64.StdEncoding.EncodeToString(make([]byte, linkBundleBytes)) + `"}`,
	"POST /api/v1/objects/{id}/share-links":      `{"version":1,"expiresAt":"2099-01-01T00:00:00Z"}`,
	"POST /api/v1/objects/{id}/attachments":      `{"attachmentId":"att_00000000000000000000000000","objectVersion":1}`,
	"POST /api/v1/containers/{id}/key-rotations": string(rotationBody(1, envJSON("dev_00000000000000000000000000", 2, 1))),
}

// orgB is a second org with one of everything a request can name, seeded with fixed rows.
type orgB struct {
	owner, member, container, object, comment, attachment, conflict, upload, invitation string
	sealed, device, reminder, link, stepUp, digest                                      string
}

func seedOrgB(t *testing.T, db *sql.DB) orgB {
	t.Helper()
	b := orgB{owner: mint(t, "usr"), member: mint(t, "usr"), container: mint(t, "cnt"), object: mint(t, "obj"), comment: mint(t, "cmt"), attachment: mint(t, "att"), conflict: mint(t, "cfl"), upload: mint(t, "ups"), invitation: mint(t, "inv"), sealed: mint(t, "shl"), device: mint(t, "dev"), link: mint(t, "lnk"), stepUp: mint(t, "rea")}
	b.reminder = strings.TrimPrefix(mint(t, "rmd"), "rmd_")
	sum := make([]byte, 32)
	_, _ = rand.Read(sum)
	b.digest = hex.EncodeToString(sum)
	session := mint(t, "ses")
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region) VALUES('org_b','active','local')`,
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at,org_id) VALUES('` + b.owner + `','b-owner','x','x',1,'t','t','org_b'),('` + b.member + `','b-member','x','x',1,'t','t','org_b')`,
		`INSERT INTO containers(id,kind,owner_user_id,key_generation,shared_generation,created_at,updated_at,org_id) VALUES('` + b.container + `','team','` + b.owner + `',1,1,'t','t','org_b')`,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('` + mint(t, "mem") + `','` + b.container + `','` + b.owner + `','owner','t'),('` + mint(t, "mem") + `','` + b.container + `','` + b.member + `','editor','t')`,
		`INSERT INTO objects(id,container_id,kind,current_version,change_seq,created_at,updated_at) VALUES('` + b.object + `','` + b.container + `','note',1,1,'t','t')`,
		`INSERT INTO blobs(digest,size_bytes,created_at,org_id) VALUES('` + b.digest + `',2,'t','org_b')`,
		`INSERT INTO blob_containers(digest,container_id,first_seen_at,org_id) VALUES('` + b.digest + `','` + b.container + `','t','org_b')`,
		`INSERT INTO object_versions(object_id,version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('` + b.object + `',1,'` + b.digest + `',2,1,1,'t','org_b')`,
		`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES('` + b.comment + `','` + b.container + `','` + b.object + `','` + b.owner + `',X'6374',1,1,'t')`,
		`INSERT INTO attachments(id,container_id,blob_digest,ciphertext_bytes,metadata_ciphertext,key_generation,change_seq,created_at,org_id) VALUES('` + b.attachment + `','` + b.container + `','` + b.digest + `',2,X'',1,1,'t','org_b')`,
		`INSERT INTO conflicts(id,object_id,container_id,base_version,current_version,blob_digest,ciphertext_bytes,key_generation,change_seq,created_at,org_id) VALUES('` + b.conflict + `','` + b.object + `','` + b.container + `',0,1,'` + b.digest + `',2,1,1,'t','org_b')`,
		`INSERT INTO upload_sessions(id,user_id,container_id,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,org_id) VALUES('` + b.upload + `','` + b.owner + `','` + b.container + `',2,65536,'t','t','2099-01-01T00:00:00Z','org_b')`,
		`INSERT INTO invitations(id,container_id,inviter_id,invitee_id,token_hash,role,created_at,expires_at) VALUES('` + b.invitation + `','` + b.container + `','` + b.owner + `','` + b.member + `','` + mint(t, "tok") + `','viewer','t','2099-01-01T00:00:00Z')`,
		`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id,org_id) VALUES('` + b.sealed + `','` + mint(t, "tok") + `',X'00000000000000000000000000000000','2099-01-01T00:00:00Z','t','` + b.owner + `','org_b')`,
		`INSERT INTO devices(id,user_id,public_key,fingerprint,secret_hash,platform,created_at) VALUES('` + b.device + `','` + b.owner + `','k','f','h','unknown','t')`,
		`INSERT INTO reminders(id,user_id,at,created_at) VALUES('` + b.reminder + `','` + b.owner + `','2099-01-01T09:00:00Z','t')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,expires_at,hard_expires_at) VALUES('` + session + `','` + b.owner + `','` + mint(t, "tok") + `','c','t','2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')`,
		`INSERT INTO link_requests(id,user_id,newcomer_session_id,commitment,created_at,expires_at) VALUES('` + b.link + `','` + b.owner + `','` + session + `',X'00','t','2099-01-01T00:00:00Z')`,
		`INSERT INTO sso_stepup(id,session_id,action,created_at,expires_at) VALUES('` + b.stepUp + `','` + session + `','user',1,4102444800)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	return b
}

// matrixIDs fills a route's path with org B's IDs, or with random IDs of the same kinds.
func (b orgB) matrixIDs(t *testing.T, route string, random bool) (string, bool) {
	t.Helper()
	path := strings.SplitN(route, " ", 2)[1]
	pick := func(prefix, real string) string {
		if !random {
			return real
		}
		if prefix == "rmd" {
			return strings.TrimPrefix(mint(t, "rmd"), "rmd_")
		}
		if prefix == "hex" {
			return strings.Repeat("ab", 32)
		}
		return mint(t, prefix)
	}
	byRoute := []struct{ prefix, id, kind string }{
		{"/containers/{id}", b.container, "cnt"}, {"/objects/{id}", b.object, "obj"}, {"/comments/{id}", b.comment, "cmt"},
		{"/attachments/{id}", b.attachment, "att"}, {"/conflicts/{id}", b.conflict, "cfl"}, {"/uploads/{id}", b.upload, "ups"},
		{"/invitations/{id}", b.invitation, "inv"}, {"/share-links/{id}", b.sealed, "shl"}, {"/devices/{id}", b.device, "dev"},
		{"/reminders/{id}", b.reminder, "rmd"}, {"/link-requests/{id}", b.link, "lnk"}, {"/step-up/{id}", b.stepUp, "rea"},
		{"/users/{id}", b.member, "usr"}, {"/teams/{id}", b.container, "cnt"},
	}
	matched := false
	for _, r := range byRoute {
		if strings.Contains(path, r.prefix) {
			path = strings.Replace(path, r.prefix, strings.Replace(r.prefix, "{id}", pick(r.kind, r.id), 1), 1)
			matched = true
		}
	}
	path = strings.ReplaceAll(path, "{userID}", pick("usr", b.member))
	path = strings.ReplaceAll(path, "{attachmentId}", pick("att", b.attachment))
	path = strings.ReplaceAll(path, "{digest}", pick("hex", b.digest))
	return path, matched && !strings.Contains(path, "{")
}

var requestIDField = regexp.MustCompile(`"requestId":"[^"]*"`)

// answer is what a caller can see of a response, bar Date and the request ID.
func answer(res *http.Response) string {
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var names []string
	for k := range res.Header {
		if k != "Date" && k != "X-Request-Id" {
			names = append(names, k+": "+strings.Join(res.Header.Values(k), ","))
		}
	}
	sort.Strings(names)
	return fmt.Sprintf("%d\n%s\n%s", res.StatusCode, strings.Join(names, "\n"), requestIDField.ReplaceAllString(string(body), `"requestId":""`))
}

// orgBRows is every row of org B a request could touch, for the unchanged check.
func orgBRows(t *testing.T, db *sql.DB, b orgB) string {
	t.Helper()
	var out strings.Builder
	for _, q := range []string{
		`SELECT * FROM users WHERE org_id='org_b' ORDER BY id`, `SELECT * FROM containers WHERE org_id='org_b' ORDER BY id`,
		`SELECT * FROM memberships WHERE container_id='` + b.container + `' ORDER BY id`, `SELECT * FROM objects WHERE container_id='` + b.container + `'`,
		`SELECT * FROM object_versions WHERE org_id='org_b'`, `SELECT * FROM comments WHERE container_id='` + b.container + `'`,
		`SELECT * FROM attachments WHERE org_id='org_b'`, `SELECT * FROM conflicts WHERE org_id='org_b'`, `SELECT * FROM upload_sessions WHERE org_id='org_b'`,
		`SELECT * FROM invitations WHERE container_id='` + b.container + `'`, `SELECT * FROM sealed_share_links WHERE org_id='org_b'`,
		`SELECT * FROM devices WHERE user_id IN ('` + b.owner + `','` + b.member + `') ORDER BY id`, `SELECT * FROM reminders WHERE user_id='` + b.owner + `'`,
		`SELECT * FROM link_requests WHERE user_id='` + b.owner + `'`, `SELECT * FROM sso_stepup WHERE id='` + b.stepUp + `'`,
		`SELECT * FROM key_envelopes WHERE container_id='` + b.container + `'`, `SELECT * FROM share_links WHERE object_id='` + b.object + `'`,
	} {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals, refs := make([]any, len(cols)), make([]any, len(cols))
			for i := range vals {
				refs[i] = &vals[i]
			}
			if err := rows.Scan(refs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&out, "%v\n", vals)
		}
		rows.Close()
	}
	return out.String()
}

// matrixRoutes is every served route that names a row in its path, bar the exempt ones.
func matrixRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, route := range servedRoutes(t) {
		if strings.Contains(route, "{") && crossOrgExempt[route] == "" {
			out = append(out, route)
		}
	}
	sort.Strings(out)
	return out
}

// A member of org A who sends org B's IDs gets exactly the answer a random ID gets, as each of
// A's roles, and B's rows do not change (spec, Isolation, "Cross-org matrix").
func TestCrossOrgMatrix(t *testing.T) {
	pairConfig = func(c *config.Config) {
		c.RateLimit = config.RateLimit{LoginPerMinute: 100000, PairingPerHour: 100000, UploadPerMinute: 100000, InvitationPerHour: 100000, LinkPollPerMinute: 100000}
	}
	t.Cleanup(func() { pairConfig = nil })
	tm := newTeam(t)
	b := seedOrgB(t, tm.owner.db)
	before := orgBRows(t, tm.owner.db, b)
	personas := map[string]*pairClient{"owner": tm.owner, "editor": tm.editor.pairClient, "viewer": tm.viewer.pairClient}
	for _, route := range matrixRoutes(t) {
		method := strings.SplitN(route, " ", 2)[0]
		real, ok := b.matrixIDs(t, route, false)
		if !ok {
			t.Errorf("%s: no org B ID for its path; add one to matrixIDs or a reason to crossOrgExempt", route)
			continue
		}
		for name, p := range personas {
			send := func(path string) string {
				var body []byte
				if method != http.MethodGet && method != http.MethodHead && method != http.MethodDelete {
					body = []byte(`{}`)
					if valid, ok := matrixBodies[route]; ok {
						body = []byte(valid)
					}
				}
				return answer(p.do(t, method, path, body, true, false))
			}
			random, _ := b.matrixIDs(t, route, true)
			if got, want := send(real), send(random); got != want {
				t.Errorf("%s as A's %s: B's ID answers\n%s\nbut a missing ID answers\n%s", route, name, got, want)
			}
		}
	}
	if after := orgBRows(t, tm.owner.db, b); after != before {
		t.Errorf("org B's rows changed:\n%s\nwant\n%s", after, before)
	}
}

// Every served route is a matrix row (it names a row in its path) or has a stated reason; routes
// that name rows only in a body, or none, act on the caller's own rows or are classified as
// public, account, device or staff routes in account_kinds_test.go.
func TestEveryRouteIsInTheCrossOrgMatrix(t *testing.T) {
	tm := newTeam(t)
	b := seedOrgB(t, tm.owner.db)
	for _, route := range matrixRoutes(t) {
		if _, ok := b.matrixIDs(t, route, false); !ok {
			t.Errorf("%s: not in the cross-org matrix and no reason given", route)
		}
	}
	for route := range crossOrgExempt {
		found := false
		for _, served := range servedRoutes(t) {
			found = found || served == route
		}
		if !found {
			t.Errorf("%s is exempt but not served", route)
		}
	}
}
