package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type shareFixture struct {
	db     *sql.DB
	server *httptest.Server
	client *http.Client
	jar    *cookiejar.Jar
	object string
}

func newShareFixture(t *testing.T) shareFixture {
	t.Helper()
	root := t.TempDir()
	store, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	secret := strings.Repeat("a", 64)
	hash, _ := auth.HashAuthSecret(secret)
	_, err = store.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, "usr_share", "share", hash, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 100000, "user", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	server := httptest.NewServer(NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, store.DB(), blobs, cfg))
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	t.Cleanup(server.Close)
	post := func(path, body string, csrf bool) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if csrf {
			for _, c := range jar.Cookies(req.URL) {
				if c.Name == "csrf_token" {
					req.Header.Set("X-CSRF-Token", c.Value)
				}
			}
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return res
	}
	res := post("/api/v1/auth/login", `{"username":"share","authSecret":"`+secret+`"}`, false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", res.StatusCode)
	}
	res.Body.Close()
	res = post("/api/v1/containers", `{"kind":"workbook","metaCiphertext":""}`, true)
	var container struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(res.Body).Decode(&container)
	res.Body.Close()
	res = post("/api/v1/containers/"+container.ID+"/objects", `{"kind":"note"}`, true)
	var object struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(res.Body).Decode(&object)
	res.Body.Close()
	return shareFixture{db: store.DB(), server: server, client: client, jar: jar, object: object.ID}
}

func (f shareFixture) csrf(req *http.Request) {
	for _, c := range f.jar.Cookies(req.URL) {
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
}

func TestObjectPutReturnsDeterministicCommitReceipt(t *testing.T) {
	f := newShareFixture(t)
	body := []byte("ciphertext")
	req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/api/v1/objects/"+f.object, bytes.NewReader(body))
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set("X-Kynotes-Key-Generation", "1")
	f.csrf(req)
	res, err := f.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("put err=%v status=%d", err, res.StatusCode)
	}
	var out struct {
		Version       int64  `json:"version"`
		Digest        string `json:"digest"`
		Bytes         int64  `json:"bytes"`
		CommitReceipt string `json:"commitReceipt"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	digest := sha256.Sum256(body)
	var storedDigest string
	var storedBytes, generation, baseVersion, changeSeq int64
	if err := f.db.QueryRow(`SELECT blob_digest,ciphertext_bytes,key_generation,base_version,change_seq FROM object_versions WHERE object_id=? AND version=1`, f.object).Scan(&storedDigest, &storedBytes, &generation, &baseVersion, &changeSeq); err != nil {
		t.Fatal(err)
	}
	if storedDigest != hex.EncodeToString(digest[:]) || storedBytes != int64(len(body)) {
		t.Fatalf("stored ciphertext metadata does not match body")
	}
	want := commitReceipt(f.object, storedDigest, 1, storedBytes, generation, baseVersion, changeSeq)
	if out.CommitReceipt != want {
		t.Fatalf("receipt=%q want=%q", out.CommitReceipt, want)
	}
}

func TestShareLinkStoresOnlyTokenHashAndServesCiphertext(t *testing.T) {
	f := newShareFixture(t)
	body := []byte("shared-ciphertext")
	req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/api/v1/objects/"+f.object, bytes.NewReader(body))
	req.Header.Set("X-Kynotes-Base-Version", "0")
	req.Header.Set("X-Kynotes-Key-Generation", "1")
	f.csrf(req)
	res, _ := f.client.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put status=%d", res.StatusCode)
	}
	shareBody := `{"version":1,"expiresAt":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`
	req, _ = http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/objects/"+f.object+"/share-links", strings.NewReader(shareBody))
	res, _ = f.client.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("share creation without csrf status=%d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/objects/"+f.object+"/share-links", strings.NewReader(shareBody))
	f.csrf(req)
	res, _ = f.client.Do(req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create link status=%d", res.StatusCode)
	}
	var link struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&link)
	res.Body.Close()
	if len(link.Token) != 43 {
		t.Fatalf("token length=%d", len(link.Token))
	}
	var stored string
	if f.db.QueryRow(`SELECT token_hash FROM share_links`).Scan(&stored) != nil || stored == link.Token {
		t.Fatal("raw token was stored")
	}
	res, _ = f.client.Get(f.server.URL + "/api/v1/share-links/" + link.Token)
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, body) || res.Header.Get("X-Kynotes-Digest") == "" || res.Header.Get("X-Kynotes-Commit-Receipt") == "" {
		t.Fatalf("fetch status=%d body=%q", res.StatusCode, got)
	}
	if _, err := f.db.Exec(`UPDATE share_links SET expires_at=?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	res, _ = f.client.Get(f.server.URL + "/api/v1/share-links/" + link.Token)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expired status=%d", res.StatusCode)
	}
}

func TestSealedShareLinkStoresCiphertextOnly(t *testing.T) {
	f := newShareFixture(t)
	sealed := base64.RawURLEncoding.EncodeToString([]byte("browser-sealed-payload"))
	body := `{"ciphertext":"` + sealed + `","expiresAt":"` + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + `"}`
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/share-links", strings.NewReader(body))
	f.csrf(req)
	res, err := f.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("create sealed link err=%v status=%d", err, res.StatusCode)
	}
	var link struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&link)
	res.Body.Close()
	res, _ = f.client.Get(f.server.URL + "/api/v1/share-links/" + link.Token)
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(got) != "browser-sealed-payload" {
		t.Fatalf("fetch sealed link status=%d body=%q", res.StatusCode, got)
	}
	var raw string
	if f.db.QueryRow(`SELECT token_hash FROM sealed_share_links`).Scan(&raw) != nil || raw == link.Token {
		t.Fatal("raw share token was stored")
	}
}
