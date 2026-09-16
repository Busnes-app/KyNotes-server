package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

type uploadClient struct {
	hc             *http.Client
	url, container string
	csrf           string
}

func newUploadClient(t *testing.T) *uploadClient {
	t.Helper()
	root := t.TempDir()
	s, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := blobstore.New(root)
	secret := strings.Repeat("a", 64)
	hash, _ := auth.HashAuthSecret(secret)
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err = s.DB().Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, "usr_upload_test", "upload", hash, salt, 100000, "now", "now")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.Server.Bind = "127.0.0.1:0"
	cfg.Limits.ChunkBytes = 4
	cfg.Limits.AttachmentMaxBytes = 100
	cfg.Limits.UserQuotaBytes = 1000000
	h := NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), b, cfg)
	srv := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	u := &uploadClient{hc: client, url: srv.URL}
	t.Cleanup(func() { srv.Close(); s.Close() })
	res := u.do(t, http.MethodPost, "/api/v1/auth/login", []byte(`{"username":"upload","authSecret":"`+secret+`"}`), false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", res.StatusCode)
	}
	res.Body.Close()
	res = u.do(t, http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("container status %d", res.StatusCode)
	}
	var c struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(res.Body).Decode(&c)
	res.Body.Close()
	u.container = c.ID
	return u
}

func (u *uploadClient) do(t *testing.T, method, path string, body []byte, csrf bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, u.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		for _, c := range u.hc.Jar.Cookies(req.URL) {
			if c.Name == "csrf_token" {
				req.Header.Set("X-CSRF-Token", c.Value)
			}
		}
	}
	res, err := u.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (u *uploadClient) upload(t *testing.T, declared int, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	body := []byte(`{"declaredBytes":` + strconv.Itoa(declared) + `,"expectedDigest":"` + hex.EncodeToString(sum[:]) + `","kind":"attachment"}`)
	res := u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", body, true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("upload create status %d", res.StatusCode)
	}
	var v struct {
		ID string `json:"uploadId"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	return v.ID
}

func (u *uploadClient) chunk(t *testing.T, id string, index int, data string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPatch, u.url+"/api/v1/uploads/"+id, strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Kynotes-Chunk-Index", strconv.Itoa(index))
	for _, c := range u.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := u.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestUploadSessionRejectsOversizeDeclaration(t *testing.T) {
	u := newUploadClient(t)
	res := u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", []byte(`{"declaredBytes":101,"kind":"attachment"}`), true)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", res.StatusCode)
	}
	res.Body.Close()
}

func TestChunkOutOfOrderIsRejectedWithExpectedNext(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, nil)
	req, _ := http.NewRequest(http.MethodPatch, u.url+"/api/v1/uploads/"+id, strings.NewReader("abcd"))
	req.Header.Set("X-Kynotes-Chunk-Index", "1")
	for _, c := range u.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := u.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var v struct {
		Next int64 `json:"nextChunk"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	if res.StatusCode != http.StatusConflict || v.Next != 0 {
		t.Fatalf("status=%d next=%d", res.StatusCode, v.Next)
	}
}

func TestIdenticalChunkRetryIsAcceptedAsNoOp(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, nil)
	for _, index := range []int{0, 0} {
		req, _ := http.NewRequest(http.MethodPatch, u.url+"/api/v1/uploads/"+id, strings.NewReader("abcd"))
		req.Header.Set("X-Kynotes-Chunk-Index", strconv.Itoa(index))
		for _, c := range u.hc.Jar.Cookies(req.URL) {
			req.AddCookie(c)
			if c.Name == "csrf_token" {
				req.Header.Set("X-CSRF-Token", c.Value)
			}
		}
		res, err := u.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("retry status=%d", res.StatusCode)
		}
		res.Body.Close()
	}
}

func TestDifferentBytesForSameChunkIndexIsRejected(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, nil)
	for index, data := range []string{"abcd", "wxyz"} {
		req, _ := http.NewRequest(http.MethodPatch, u.url+"/api/v1/uploads/"+id, strings.NewReader(data))
		req.Header.Set("X-Kynotes-Chunk-Index", strconv.Itoa(index))
		for _, c := range u.hc.Jar.Cookies(req.URL) {
			req.AddCookie(c)
			if c.Name == "csrf_token" {
				req.Header.Set("X-CSRF-Token", c.Value)
			}
		}
		res, err := u.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("chunk status=%d", res.StatusCode)
		}
		res.Body.Close()
	}
	req, _ := http.NewRequest(http.MethodPatch, u.url+"/api/v1/uploads/"+id, strings.NewReader("bad!"))
	req.Header.Set("X-Kynotes-Chunk-Index", "1")
	for _, c := range u.hc.Jar.Cookies(req.URL) {
		req.AddCookie(c)
		if c.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	res, err := u.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("different retry status=%d", res.StatusCode)
	}
	res.Body.Close()
}

func TestWrongSizedMiddleChunkIsRejected(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, nil)
	if res := u.chunk(t, id, 0, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	if res := u.chunk(t, id, 1, "abc"); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("middle status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
}

func TestExceedingDeclaredBytesFailsSession(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 5, nil)
	if res := u.chunk(t, id, 0, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	if res := u.chunk(t, id, 1, "ef"); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("excess status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	res := u.do(t, http.MethodGet, "/api/v1/uploads/"+id, nil, false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status lookup=%d", res.StatusCode)
	}
	var v struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	if v.Status != "failed" {
		t.Fatalf("status=%q", v.Status)
	}
}

func TestInterruptedUploadResumesFromNextChunk(t *testing.T) {
	u := newUploadClient(t)
	id := u.upload(t, 8, nil)
	if res := u.chunk(t, id, 0, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	res := u.do(t, http.MethodGet, "/api/v1/uploads/"+id, nil, false)
	var v struct {
		Next int `json:"nextChunk"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	if v.Next != 1 {
		t.Fatalf("next=%d", v.Next)
	}
	if res = u.chunk(t, id, 1, "efgh"); res.StatusCode != http.StatusOK {
		t.Fatalf("resume status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
}

func TestCorruptedChunkChangesDigestAndFailsFinalize(t *testing.T) {
	u := newUploadClient(t)
	data := []byte("abcdefgh")
	correct := sha256.Sum256(data)
	body := []byte(`{"declaredBytes":8,"expectedDigest":"` + hex.EncodeToString(correct[:]) + `","kind":"attachment"}`)
	res := u.do(t, http.MethodPost, "/api/v1/containers/"+u.container+"/uploads", body, true)
	var v struct {
		ID string `json:"uploadId"`
	}
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	if res = u.chunk(t, v.ID, 0, "abcd"); res.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	if res = u.chunk(t, v.ID, 1, "wxyz"); res.StatusCode != http.StatusOK {
		t.Fatalf("second status=%d", res.StatusCode)
	} else {
		res.Body.Close()
	}
	res = u.do(t, http.MethodPost, "/api/v1/uploads/"+v.ID+"/finalize", []byte(`{"metadataCiphertext":"","keyGeneration":1}`), true)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("finalize status=%d", res.StatusCode)
	}
	res.Body.Close()
}

func TestAttachmentHasNoUpdateRoute(t *testing.T) {
	u := newUploadClient(t)
	res := u.do(t, http.MethodPut, "/api/v1/attachments/att_missing", []byte("x"), true)
	if res.StatusCode != http.StatusMethodNotAllowed && res.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", res.StatusCode)
	}
	res.Body.Close()
}
