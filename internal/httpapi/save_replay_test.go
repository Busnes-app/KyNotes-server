package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSaveReplayReturnsTheVersionItCommitted(t *testing.T) {
	f := newShareFixture(t)
	send := func(key string, base int64) int64 {
		req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/api/v1/objects/"+f.object, bytes.NewBufferString("ciphertext"))
		req.Header.Set("X-Kynotes-Base-Version", strconv.FormatInt(base, 10))
		req.Header.Set("X-Kynotes-Key-Generation", strconv.FormatInt(f.generation, 10))
		req.Header.Set(keySchemeHeader, keySchemeShared)
		req.Header.Set("Idempotency-Key", key)
		f.csrf(req)
		res, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out struct{ Version int64 }
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != 200 {
			t.Fatalf("save=%d %+v %v", res.StatusCode, out, err)
		}
		return out.Version
	}
	if got := send("first", 0); got != 1 {
		t.Fatal(got)
	}
	if got := send("next", 1); got != 2 {
		t.Fatal(got)
	}
	if got := send("first", 0); got != 1 {
		t.Fatalf("replayed version=%d want original1", got)
	}
}

type heldSaveBody struct {
	body    *bytes.Reader
	release <-chan struct{}
}

func (b heldSaveBody) Read(p []byte) (int, error) { <-b.release; return b.body.Read(p) }
func TestConcurrentSaveReplayMakesOneVersion(t *testing.T) {
	f := newShareFixture(t)
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	type result struct {
		status  int
		version int64
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			req, _ := http.NewRequest(http.MethodPut, f.server.URL+"/api/v1/objects/"+f.object, heldSaveBody{bytes.NewReader([]byte("ciphertext")), release})
			req.ContentLength = 10
			req.Header.Set("Expect", "100-continue")
			req.Header.Set("X-Kynotes-Base-Version", "0")
			req.Header.Set("X-Kynotes-Key-Generation", strconv.FormatInt(f.generation, 10))
			req.Header.Set(keySchemeHeader, keySchemeShared)
			req.Header.Set("Idempotency-Key", "shared-edit")
			f.csrf(req)
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{Got100Continue: func() { arrived <- struct{}{} }}))
			res, err := f.client.Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer res.Body.Close()
			var out struct{ Version int64 }
			err = json.NewDecoder(res.Body).Decode(&out)
			results <- result{res.StatusCode, out.Version, err}
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("both requests did not pass the pre-body replay check")
		}
	}
	once.Do(func() { close(release) })
	for range 2 {
		r := <-results
		if r.err != nil || r.status != 200 || r.version != 1 {
			t.Fatalf("concurrent replay=%+v", r)
		}
	}
	var versions, conflicts int
	if err := f.db.QueryRow(`SELECT (SELECT COUNT(*) FROM object_versions WHERE object_id=?1),(SELECT COUNT(*) FROM conflicts WHERE object_id=?1)`, f.object).Scan(&versions, &conflicts); err != nil || versions != 1 || conflicts != 0 {
		t.Fatalf("versions=%d conflicts=%d %v", versions, conflicts, err)
	}
}
