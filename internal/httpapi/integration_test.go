package httpapi

import (
	"bytes"
	"crypto/sha256"
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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoginContainerObjectLifecycle(t *testing.T) {
	root := t.TempDir()
	s, e := storage.Open(filepath.Join(root, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b, e := blobstore.New(root)
	if e != nil {
		t.Fatal(e)
	}
	secret := strings.Repeat("a", 64)
	hash, e := auth.HashAuthSecret(secret)
	if e != nil {
		t.Fatal(e)
	}
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, e = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, "usr_integration", "alice", hash, salt, 100000, "user", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if e != nil {
		t.Fatal(e)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Server.Bind = "127.0.0.1:0"
	h := NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), b, cfg)
	srv := httptest.NewServer(h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	post := func(path string, body string, csrf bool) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if csrf {
			for _, x := range jar.Cookies(req.URL) {
				if x.Name == "csrf_token" {
					req.Header.Set("X-CSRF-Token", x.Value)
				}
			}
		}
		res, er := c.Do(req)
		if er != nil {
			t.Fatal(er)
		}
		return res
	}
	r := post("/api/v1/auth/login", `{"username":"alice","authSecret":"`+secret+`"}`, false)
	if r.StatusCode != 200 {
		t.Fatalf("login %d", r.StatusCode)
	}
	r.Body.Close()
	r = post("/api/v1/containers", `{"kind":"workbook","metaCiphertext":"`+base64.StdEncoding.EncodeToString([]byte("cipher"))+`"}`, true)
	if r.StatusCode != 200 {
		t.Fatalf("container %d", r.StatusCode)
	}
	var container struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&container)
	r.Body.Close()
	r = post("/api/v1/containers/"+container.ID+"/objects", `{"kind":"note"}`, true)
	if r.StatusCode != 200 {
		t.Fatalf("object %d", r.StatusCode)
	}
	var object struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&object)
	r.Body.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/objects/"+object.ID, strings.NewReader("ciphertext-v1"))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set("X-Kynotes-Key-Generation", "1")
	for _, x := range jar.Cookies(req.URL) {
		if x.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", x.Value)
		}
	}
	r, e = c.Do(req)
	if e != nil || r.StatusCode != 200 {
		t.Fatalf("save: %v status=%d", e, r.StatusCode)
	}
	r.Body.Close()
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/api/v1/objects/"+object.ID, strings.NewReader("ciphertext-stale"))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set("X-Kynotes-Key-Generation", "1")
	for _, x := range jar.Cookies(req.URL) {
		if x.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", x.Value)
		}
	}
	r, e = c.Do(req)
	if e != nil || r.StatusCode != 409 {
		t.Fatalf("conflict: %v status=%d", e, r.StatusCode)
	}
	r.Body.Close()
	data := []byte("attachment-ciphertext")
	sum := sha256.Sum256(data)
	r = post("/api/v1/containers/"+container.ID+"/uploads", `{"declaredBytes":`+strconv.Itoa(len(data))+`,"expectedDigest":"`+hex.EncodeToString(sum[:])+`","kind":"attachment"}`, true)
	if r.StatusCode != 200 {
		t.Fatalf("upload create %d", r.StatusCode)
	}
	var upload struct {
		ID string `json:"uploadId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&upload)
	r.Body.Close()
	req, _ = http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/uploads/"+upload.ID, bytes.NewReader(data))
	req.Header.Set("X-Kynotes-Chunk-Index", "0")
	for _, x := range jar.Cookies(req.URL) {
		if x.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", x.Value)
		}
	}
	r, e = c.Do(req)
	if e != nil || r.StatusCode != 200 {
		t.Fatalf("chunk %v %d", e, r.StatusCode)
	}
	r.Body.Close()
	r = post("/api/v1/uploads/"+upload.ID+"/finalize", `{"metadataCiphertext":"","keyGeneration":1}`, true)
	if r.StatusCode != 200 {
		t.Fatalf("finalize %d", r.StatusCode)
	}
	r.Body.Close()
}
