package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/tenancy-golden from this build")

// legacySchema is the last migration before tenancy (0031). The golden's database is built
// from exactly these files, so the upgrade it proves is the one an install makes.
const legacySchema = 31

// goldenDSN is storage.open's DSN, so the legacy phase runs the same SQLite as a server.
func goldenDSN(path string) string {
	return fmt.Sprintf("file:%s?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)", path)
}

func legacyDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", goldenDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("..", "storage", "migrations", "*.sql"))
	if err != nil || len(files) < legacySchema {
		t.Fatalf("migrations: %d %v", len(files), err)
	}
	sort.Strings(files)
	for i, f := range files[:legacySchema] {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err = db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,'2026-01-01T00:00:00Z')`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// goldenClient records every answer, with minted IDs, tokens and clock values replaced by
// placeholders numbered in order of first appearance, so two runs compare byte for byte.
type goldenClient struct {
	url  string
	hc   *http.Client
	log  *strings.Builder
	seen map[string]string
}

var (
	goldenTime  = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)`)
	goldenID    = regexp.MustCompile(`\b[a-z]{3}_[0-9a-hjkmnp-tv-z]{26}\b`)
	goldenToken = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
	goldenAgo   = regexp.MustCompile(`"\d+ ?s ago"`)
)

func (g *goldenClient) norm(s string) string {
	s = goldenTime.ReplaceAllString(s, "<time>")
	s = goldenAgo.ReplaceAllString(s, `"<ago>"`)
	for _, re := range []*regexp.Regexp{goldenID, goldenToken} {
		s = re.ReplaceAllStringFunc(s, func(v string) string {
			if p, ok := g.seen[v]; ok {
				return p
			}
			kind := "tok"
			if re == goldenID {
				kind = v[:3]
			}
			p := fmt.Sprintf("<%s%d>", kind, len(g.seen)+1)
			g.seen[v] = p
			return p
		})
	}
	return s
}

func (g *goldenClient) do(t *testing.T, step, method, path string, headers map[string]string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, g.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(keySchemeHeader, keySchemeShared)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range g.hc.Jar.Cookies(req.URL) {
		if c.Name == "csrf_token" && method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := g.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var names []string
	for k := range res.Header {
		if k != "Date" && k != "X-Request-Id" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	fmt.Fprintf(g.log, "== %s: %s %s\n%d\n", step, method, g.norm(path), res.StatusCode)
	for _, k := range names {
		fmt.Fprintf(g.log, "%s: %s\n", k, g.norm(strings.Join(res.Header.Values(k), "; ")))
	}
	shown := g.norm(string(out))
	// The audit list orders rows of one second by their random ID; compare it as a set.
	var rows []json.RawMessage
	if strings.HasSuffix(path, "/admin/audit") && json.Unmarshal(out, &rows) == nil {
		items := make([]string, len(rows))
		for i, row := range rows {
			items[i] = g.norm(string(row))
		}
		sort.Strings(items)
		shown = "[" + strings.Join(items, ",") + "]"
	}
	fmt.Fprintf(g.log, "\n%s\n\n", shown)
	return res.StatusCode, out
}

func goldenServer(t *testing.T, db *sql.DB, root string) string {
	t.Helper()
	blobs, err := blobstore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Server.Bind = "127.0.0.1:0"
	cfg.Secrets.PairingSecret = strings.Repeat("p", 32)
	srv := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, db, blobs, cfg))
	t.Cleanup(srv.Close)
	return srv.URL
}

func goldenField(t *testing.T, body []byte, field string) string {
	t.Helper()
	m := regexp.MustCompile(`"` + field + `":"([^"]*)"`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("no %s in %s", field, body)
	}
	return string(m[1])
}

var updateLegacy = flag.Bool("update-legacy", false, "rewrite testdata/tenancy-golden/legacy.* (only on the release before tenancy)")

// goldenFixture names what the legacy database holds, for the requests after the upgrade.
type goldenFixture struct {
	Notebook, Team, Page, TeamPage, Attachment, Token, Generation, TeamGeneration string
}

func goldenPath(name string) string { return filepath.Join("testdata", "tenancy-golden", name) }

// writeLegacy runs the release before tenancy: a 0031 database, notes written through its API,
// then its rows dumped as SQL and its blob files copied. Only that release can run it.
func writeLegacy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kynotes.sqlite")
	db := legacyDatabase(t, path)
	files, _ := filepath.Glob(filepath.Join("..", "storage", "migrations", "*.sql"))
	if len(files) != legacySchema {
		t.Fatalf("-update-legacy runs only on the release before tenancy (%d migrations, want %d)", len(files), legacySchema)
	}
	secret := strings.Repeat("a", 64)
	hash, err := auth.HashAuthSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	for _, u := range []struct{ id, name, kind string }{{"usr_golden_alice", "alice", "user"}, {"usr_golden_bob", "bob", "user"}, {"usr_golden_admin", "root", "admin"}} {
		if _, err = db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,account_kind,created_at,updated_at) VALUES(?,?,?,?,100000,?,?,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, u.id, u.name, hash, salt, u.kind, u.kind); err != nil {
			t.Fatal(err)
		}
	}
	url := goldenServer(t, db, root)
	jar, _ := cookiejar.New(nil)
	g := &goldenClient{url: url, hc: &http.Client{Jar: jar}, log: &strings.Builder{}, seen: map[string]string{}}
	jar2, _ := cookiejar.New(nil)
	bob := &goldenClient{url: url, hc: &http.Client{Jar: jar2}, log: g.log, seen: g.seen}
	ok := func(code int, out []byte) []byte {
		t.Helper()
		if code != http.StatusOK {
			t.Fatalf("%d %s", code, out)
		}
		return out
	}
	ok(g.do(t, "login", http.MethodPost, "/api/v1/auth/login", nil, []byte(`{"username":"alice","authSecret":"`+secret+`"}`)))
	ok(bob.do(t, "login", http.MethodPost, "/api/v1/auth/login", nil, []byte(`{"username":"bob","authSecret":"`+secret+`"}`)))
	var f goldenFixture
	f.Notebook = goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/containers", nil, []byte(`{"kind":"workbook","metaCiphertext":""}`))), "id")
	f.Team = goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/containers", nil, []byte(`{"kind":"team","metaCiphertext":""}`))), "id")
	if _, err = db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,approved,created_at) VALUES('mem_golden_bob',?,'usr_golden_bob','editor',1,'2026-01-01T00:00:00Z')`, f.Team); err != nil {
		t.Fatal(err)
	}
	f.Generation = strconv.FormatInt(keyForTest(t, db, f.Notebook, "usr_golden_alice"), 10)
	f.TeamGeneration = strconv.FormatInt(keyForTest(t, db, f.Team, "usr_golden_alice", "usr_golden_bob"), 10)
	f.Page = goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/containers/"+f.Notebook+"/objects", nil, []byte(`{"kind":"note"}`))), "id")
	save := map[string]string{"Content-Type": "application/octet-stream", "X-Kynotes-Base-Version": "0", "X-Kynotes-Key-Generation": f.Generation}
	ok(g.do(t, "", http.MethodPut, "/api/v1/objects/"+f.Page, save, []byte("ciphertext-v1")))
	if code, out := g.do(t, "", http.MethodPut, "/api/v1/objects/"+f.Page, save, []byte("ciphertext-stale")); code != http.StatusConflict {
		t.Fatalf("conflict %d %s", code, out)
	}
	f.TeamPage = goldenField(t, ok(bob.do(t, "", http.MethodPost, "/api/v1/containers/"+f.Team+"/objects", nil, []byte(`{"kind":"note"}`))), "id")
	ok(bob.do(t, "", http.MethodPut, "/api/v1/objects/"+f.TeamPage, map[string]string{"Content-Type": "application/octet-stream", "X-Kynotes-Base-Version": "0", "X-Kynotes-Key-Generation": f.TeamGeneration}, []byte("team-ciphertext")))
	ok(g.do(t, "", http.MethodPost, "/api/v1/objects/"+f.TeamPage+"/comments", nil, []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":`+f.TeamGeneration+`}`)))
	data := []byte("attachment-ciphertext")
	sum := sha256.Sum256(data)
	upload := goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/containers/"+f.Notebook+"/uploads", nil, []byte(`{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"attachment"}`))), "uploadId")
	ok(g.do(t, "", http.MethodPatch, "/api/v1/uploads/"+upload, map[string]string{"Content-Type": "application/octet-stream", "X-Kynotes-Chunk-Index": "0"}, data))
	f.Attachment = goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/uploads/"+upload+"/finalize", nil, []byte(`{"metadataCiphertext":"","keyGeneration":`+f.Generation+`}`))), "attachmentId")
	// A year out, so the fixture's links stay live; the server caps sealed links at 30 days
	// from creation, so the sealed one is written straight away and its expiry moved after.
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	ok(g.do(t, "", http.MethodPost, "/api/v1/share-links", nil, []byte(`{"ciphertext":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`","expiresAt":"`+expires+`"}`)))
	f.Token = goldenField(t, ok(g.do(t, "", http.MethodPost, "/api/v1/objects/"+f.Page+"/share-links", nil, []byte(`{"version":1,"expiresAt":"`+expires+`"}`))), "token")
	if _, err = db.Exec(`UPDATE share_links SET expires_at='2099-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_share_links SET expires_at='2099-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	var dump strings.Builder
	tables, err := db.Query(`SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'schema_migrations' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		_ = tables.Scan(&n)
		names = append(names, n)
	}
	tables.Close()
	for _, n := range names {
		rows, err := db.Query(`SELECT * FROM "` + n + `" ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals, refs := make([]any, len(cols)), make([]any, len(cols))
			for i := range vals {
				refs[i] = &vals[i]
			}
			if err = rows.Scan(refs...); err != nil {
				t.Fatal(err)
			}
			lits := make([]string, len(vals))
			for i, v := range vals {
				switch v := v.(type) {
				case nil:
					lits[i] = "NULL"
				case int64:
					lits[i] = strconv.FormatInt(v, 10)
				case float64:
					lits[i] = strconv.FormatFloat(v, 'g', -1, 64)
				case string:
					lits[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
				case []byte:
					lits[i] = "X'" + hex.EncodeToString(v) + "'"
				default:
					t.Fatalf("%s: %T", n, v)
				}
			}
			fmt.Fprintf(&dump, "INSERT OR REPLACE INTO \"%s\"(%s) VALUES(%s);\n", n, strings.Join(cols, ","), strings.Join(lits, ","))
		}
		rows.Close()
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	fixture, _ := json.MarshalIndent(f, "", "  ")
	_ = os.RemoveAll(goldenPath("blobs"))
	for _, w := range []struct {
		name string
		data []byte
	}{{"legacy.sql", []byte(dump.String())}, {"legacy.json", append(fixture, '\n')}} {
		if err = os.MkdirAll(goldenPath(""), 0o755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(goldenPath(w.name), w.data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.CopyFS(goldenPath("blobs"), os.DirFS(filepath.Join(root, "blobs"))); err != nil {
		t.Fatal(err)
	}
}

// loadLegacy rebuilds the legacy database: migrations 0001 to 0031 exactly as an install ran
// them, then the old release's rows and blob files.
func loadLegacy(t *testing.T, root string) (string, goldenFixture) {
	t.Helper()
	path := filepath.Join(root, "kynotes.sqlite")
	db := legacyDatabase(t, path)
	dump, err := os.ReadFile(goldenPath("legacy.sql"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`PRAGMA defer_foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(string(dump)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.CopyFS(filepath.Join(root, "blobs"), os.DirFS(goldenPath("blobs"))); err != nil {
		t.Fatal(err)
	}
	var f goldenFixture
	raw, err := os.ReadFile(goldenPath("legacy.json"))
	if err == nil {
		err = json.Unmarshal(raw, &f)
	}
	if err != nil {
		t.Fatal(err)
	}
	return path, f
}

// TestSingleTenantUpgradeGolden upgrades a database the release before tenancy wrote
// (testdata/tenancy-golden/legacy.*) with storage.Open, then reads and writes through the API.
// Every answer must match testdata/tenancy-golden/upgrade.txt, which that release recorded.
// -update-golden rewrites it; use it only when a single-tenant answer is meant to change.
func TestSingleTenantUpgradeGolden(t *testing.T) {
	storage.SkipOnPostgres(t, "it upgrades a SQLite install")
	if *updateLegacy {
		writeLegacy(t)
	}
	root := t.TempDir()
	path, f := loadLegacy(t, root)
	store, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	url := goldenServer(t, store.DB(), root)
	log := &strings.Builder{}
	seen := map[string]string{}
	client := func() *goldenClient {
		jar, _ := cookiejar.New(nil)
		return &goldenClient{url: url, hc: &http.Client{Jar: jar}, log: log, seen: seen}
	}
	secret := strings.Repeat("a", 64)
	login := func(g *goldenClient, step, name string) {
		if code, out := g.do(t, step, http.MethodPost, "/api/v1/auth/login", nil, []byte(`{"username":"`+name+`","authSecret":"`+secret+`"}`)); code != http.StatusOK {
			t.Fatalf("%s: %d %s", step, code, out)
		}
	}
	alice, bob, admin := client(), client(), client()
	login(alice, "a1 alice login", "alice")
	login(bob, "a2 bob login", "bob")
	login(admin, "a3 admin login", "root")
	reads := func(prefix string) {
		alice.do(t, prefix+" session", http.MethodGet, "/api/v1/auth/session", nil, nil)
		alice.do(t, prefix+" containers", http.MethodGet, "/api/v1/containers", nil, nil)
		bob.do(t, prefix+" bob containers", http.MethodGet, "/api/v1/containers", nil, nil)
		alice.do(t, prefix+" changes", http.MethodGet, "/api/v1/containers/"+f.Notebook+"/changes", nil, nil)
		alice.do(t, prefix+" team changes", http.MethodGet, "/api/v1/containers/"+f.Team+"/changes", nil, nil)
		alice.do(t, prefix+" members", http.MethodGet, "/api/v1/containers/"+f.Team+"/members", nil, nil)
		alice.do(t, prefix+" envelopes", http.MethodGet, "/api/v1/containers/"+f.Team+"/envelopes", nil, nil)
		alice.do(t, prefix+" page", http.MethodGet, "/api/v1/objects/"+f.Page, nil, nil)
		bob.do(t, prefix+" team page", http.MethodGet, "/api/v1/objects/"+f.TeamPage, nil, nil)
		alice.do(t, prefix+" comments", http.MethodGet, "/api/v1/objects/"+f.TeamPage+"/comments", nil, nil)
		alice.do(t, prefix+" attachments", http.MethodGet, "/api/v1/objects/"+f.Page+"/attachments", nil, nil)
		alice.do(t, prefix+" attachment", http.MethodGet, "/api/v1/attachments/"+f.Attachment, nil, nil)
		alice.do(t, prefix+" links", http.MethodGet, "/api/v1/share-links", nil, nil)
		client().do(t, prefix+" public link", http.MethodGet, "/api/v1/share-links/"+f.Token, nil, nil)
		bob.do(t, prefix+" bob reads alice's notebook", http.MethodGet, "/api/v1/containers/"+f.Notebook+"/changes", nil, nil)
		admin.do(t, prefix+" admin users", http.MethodGet, "/api/v1/admin/users", nil, nil)
		admin.do(t, prefix+" admin settings", http.MethodGet, "/api/v1/admin/settings", nil, nil)
		admin.do(t, prefix+" admin teams", http.MethodGet, "/api/v1/admin/teams", nil, nil)
		admin.do(t, prefix+" admin audit", http.MethodGet, "/api/v1/admin/audit", nil, nil)
	}
	save := func(g *goldenClient, step, object, base, gen, body string) {
		g.do(t, step, http.MethodPut, "/api/v1/objects/"+object, map[string]string{"Content-Type": "application/octet-stream", "X-Kynotes-Base-Version": base, "X-Kynotes-Key-Generation": gen}, []byte(body))
	}
	reads("b")
	save(alice, "c1 save", f.Page, "1", f.Generation, "ciphertext-v2")
	save(alice, "c2 stale save", f.Page, "1", f.Generation, "ciphertext-stale-2")
	bob.do(t, "c3 bob comments", http.MethodPost, "/api/v1/objects/"+f.TeamPage+"/comments", nil, []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":`+f.TeamGeneration+`}`))
	_, out := alice.do(t, "c4 new notebook", http.MethodPost, "/api/v1/containers", nil, []byte(`{"kind":"workbook","metaCiphertext":""}`))
	fresh := goldenField(t, out, "id")
	_, out = alice.do(t, "c5 page in it", http.MethodPost, "/api/v1/containers/"+fresh+"/objects", nil, []byte(`{"kind":"note"}`))
	save(alice, "c6 unkeyed save", goldenField(t, out, "id"), "0", "1", "ciphertext")
	data := []byte("second-attachment")
	sum := sha256.Sum256(data)
	_, out = alice.do(t, "c7 upload", http.MethodPost, "/api/v1/containers/"+f.Notebook+"/uploads", nil, []byte(`{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"attachment"}`))
	upload := goldenField(t, out, "uploadId")
	alice.do(t, "c8 chunk", http.MethodPatch, "/api/v1/uploads/"+upload, map[string]string{"Content-Type": "application/octet-stream", "X-Kynotes-Chunk-Index": "0"}, data)
	alice.do(t, "c9 finalize", http.MethodPost, "/api/v1/uploads/"+upload+"/finalize", nil, []byte(`{"metadataCiphertext":"","keyGeneration":`+f.Generation+`}`))
	alice.do(t, "c10 sealed link", http.MethodPost, "/api/v1/share-links", nil, []byte(`{"ciphertext":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))+`","expiresAt":"`+time.Now().UTC().Add(time.Hour).Format(time.RFC3339)+`"}`))
	alice.do(t, "c11 delete page", http.MethodDelete, "/api/v1/objects/"+f.Page, nil, nil)
	reads("d")

	golden := goldenPath("upgrade.txt")
	if *updateGolden || *updateLegacy {
		if err := os.WriteFile(golden, []byte(log.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := log.String(); got != string(want) {
		t.Errorf("single-tenant answers changed (diff against %s):\n%s", golden, firstDifference(got, string(want)))
	}
}

func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			from := max(0, i-6)
			return fmt.Sprintf("line %d\n got: %q\nwant: %q\ncontext:\n%s", i+1, a, b, strings.Join(g[from:min(len(g), i+1)], "\n"))
		}
	}
	return ""
}
