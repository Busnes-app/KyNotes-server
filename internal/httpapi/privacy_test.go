package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type privacyRunResult struct {
	root, marker string
	log          bytes.Buffer
	responses    []string
	secrets      []string
	db           *sql.DB
}

func runPrivacy(t *testing.T) privacyRunResult {
	t.Helper()
	root := t.TempDir()
	s, e := storage.Open(filepath.Join(root, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := blobstore.New(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	secret := strings.Repeat("a", 64)
	hash, _ := auth.HashAuthSecret(secret)
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, e = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, "usr_privacy", "privacy", hash, salt, 100000, "user", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if e != nil {
		t.Fatal(e)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	var log bytes.Buffer
	h := NewRouter(logging.New(&log, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), b, cfg)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	responses := []string{}
	do := func(method, path string, body io.Reader, csrf bool) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, body)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if csrf {
			for _, c := range jar.Cookies(req.URL) {
				if c.Name == "csrf_token" {
					req.Header.Set("X-CSRF-Token", c.Value)
				}
			}
		}
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		bb, _ := io.ReadAll(r.Body)
		r.Body.Close()
		responses = append(responses, string(bb))
		r.Body = io.NopCloser(bytes.NewReader(bb))
		return r
	}
	r := do("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"privacy","authSecret":"`+secret+`"}`), false)
	if r.StatusCode != 200 {
		t.Fatalf("login %d", r.StatusCode)
	}
	var secrets []string
	for _, cookie := range jar.Cookies(r.Request.URL) {
		if cookie.Value != "" {
			secrets = append(secrets, cookie.Value)
		}
	}
	r = do("POST", "/api/v1/containers", strings.NewReader(`{"kind":"workbook","metaCiphertext":""}`), true)
	if r.StatusCode != 200 {
		t.Fatalf("container %d", r.StatusCode)
	}
	var c struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&c)
	r = do("POST", "/api/v1/containers/"+c.ID+"/objects", strings.NewReader(`{"kind":"note"}`), true)
	var o struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&o)
	marker := "privacy-marker-never-on-server"
	sum := sha256.Sum256([]byte(marker))
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/objects/"+o.ID, bytes.NewReader(sum[:]))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set("X-Kynotes-Key-Generation", "1")
	for _, c := range jar.Cookies(req.URL) {
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	r, e = client.Do(req)
	if e != nil || r.StatusCode != 200 {
		t.Fatalf("save %v %d", e, r.StatusCode)
	}
	bb, _ := io.ReadAll(r.Body)
	r.Body.Close()
	responses = append(responses, string(bb))
	return privacyRunResult{root: root, marker: marker, log: log, responses: responses, secrets: append(secrets, secret), db: s.DB()}
}
func TestMarkerAbsentFromLogs(t *testing.T) {
	r := runPrivacy(t)
	if bytes.Contains(r.log.Bytes(), []byte(r.marker)) {
		t.Fatal("marker in logs")
	}
}
func TestMarkerAbsentFromEveryHTTPResponse(t *testing.T) {
	r := runPrivacy(t)
	for _, v := range r.responses {
		if strings.Contains(v, r.marker) {
			t.Fatal("marker in response")
		}
	}
}
func TestMarkerAbsentFromEverySQLiteColumn(t *testing.T) {
	r := runPrivacy(t)
	rows, e := r.db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		_ = rows.Scan(&table)
		if table == "schema_migrations" {
			continue
		}
		q := `SELECT * FROM ` + "\"" + strings.ReplaceAll(table, "\"", "\"\"") + "\""
		rs, e := r.db.Query(q)
		if e != nil {
			t.Fatal(e)
		}
		cols, _ := rs.Columns()
		for rs.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = rs.Scan(ptrs...)
			for _, v := range vals {
				if strings.Contains(stringify(v), r.marker) {
					t.Fatalf("marker in table %s", table)
				}
			}
		}
		rs.Close()
	}
}
func TestMarkerAbsentFromBlobDirectory(t *testing.T) {
	r := runPrivacy(t)
	e := filepath.Walk(r.root, func(path string, info os.FileInfo, e error) error {
		if e != nil || info.IsDir() {
			return e
		}
		b, _ := os.ReadFile(path)
		if bytes.Contains(b, []byte(r.marker)) {
			t.Fatalf("marker in %s", path)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestMarkerAbsentFromBackupArchive(t *testing.T) {
	r := runPrivacy(t)
	dst := t.TempDir()
	e := filepath.Walk(r.root, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(r.root, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		out, e := os.Create(target)
		if e != nil {
			return e
		}
		_, e = io.Copy(out, in)
		_ = out.Close()
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = filepath.Walk(dst, func(path string, info os.FileInfo, e error) error {
		if e != nil || info.IsDir() {
			return e
		}
		b, _ := os.ReadFile(path)
		if bytes.Contains(b, []byte(r.marker)) {
			t.Fatalf("marker in backup")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestNoPrivateKeyOrTokenMaterialInAnyTable(t *testing.T) {
	r := runPrivacy(t)
	for _, secret := range append(r.secrets, r.marker) {
		rows, _ := r.db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
		for rows.Next() {
			var table string
			_ = rows.Scan(&table)
			rs, e := r.db.Query(`SELECT * FROM "` + strings.ReplaceAll(table, "\"", "\"\"") + `"`)
			if e != nil {
				continue
			}
			cols, _ := rs.Columns()
			for rs.Next() {
				v := make([]any, len(cols))
				p := make([]any, len(v))
				for i := range v {
					p[i] = &v[i]
				}
				_ = rs.Scan(p...)
				for _, x := range v {
					if strings.Contains(stringify(x), secret) {
						t.Fatalf("sensitive material in %s", table)
					}
				}
			}
			rs.Close()
		}
		rows.Close()
	}
}
func stringify(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x) + " " + hex.EncodeToString(x)
	default:
		return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(stringifyJSON(x)), "\n", ""))
	}
}
func stringifyJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func TestMarkerAbsentFromPushPayloads(t *testing.T) {
	r := runPrivacy(t)
	if bytes.Contains(PushPayload("cnt_test", 1), []byte(r.marker)) {
		t.Fatal("marker in push payload")
	}
}
