package blobstore

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
)

// The disposable signature-checking, versioned S3 server CI starts (KY_TEST_S3_*), behind a
// verified TLS proxy that can make it lie in one way at a time.
func versionedS3(t *testing.T) (shareds3.Config, *atomic.Value) {
	t.Helper()
	endpoint := os.Getenv("KY_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set KY_TEST_S3_* for the disposable versioned S3 server")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("the qualification fixture must be loopback HTTP, never a live store")
	}
	var lie atomic.Value
	lie.Store("")
	proxy := httputil.NewSingleHostReverseProxy(u)
	forward := proxy.ServeHTTP
	proxy.ModifyResponse = func(resp *http.Response) error {
		r := resp.Request
		switch lie.Load() {
		case "conditional": // accepts an If-None-Match: * PUT on an existing key
			if r.Method == http.MethodPut && resp.StatusCode == http.StatusPreconditionFailed {
				resp.StatusCode = http.StatusOK
			}
		case "age":
			resp.Header.Del("Last-Modified")
		case "replaced": // refuses the second PUT, yet serves its bytes
			if r.Method == http.MethodGet && r.URL.RawQuery == "" && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				resp.Body = io.NopCloser(strings.NewReader("other"))
			}
		case "unsigned": // answers a bad signature as if it had checked nothing
			if resp.StatusCode == http.StatusForbidden {
				resp.StatusCode = http.StatusNotFound
			}
		}
		return nil
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lie.Load() == "erasure" && r.Method == http.MethodDelete && r.URL.Query().Has("versionId") {
			w.WriteHeader(http.StatusNoContent) // claims to delete a version it keeps
			return
		}
		forward(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := shareds3.Config{Endpoint: srv.URL, Bucket: os.Getenv("KY_TEST_S3_BUCKET"), Region: "us-east-1", AccessKey: os.Getenv("KY_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KY_TEST_S3_SECRET_KEY"), HTTP: srv.Client()}
	t.Cleanup(func() {
		lie.Store("")
		c, err := shareds3.New(cfg)
		if err == nil {
			err = c.DeletePrefix(context.Background(), "qualify/")
		}
		if err != nil {
			t.Error("fixture cleanup", err)
		}
	})
	return cfg, &lie
}

// The real versioned server qualifies and leaves nothing behind; each provider behavior
// multi mode relies on, broken alone, fails qualification at its own step.
func TestProviderQualificationOnVersionedS3(t *testing.T) {
	cfg, lie := versionedS3(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	q, err := QualifyProvider(ctx, cfg, time.Now)
	if err != nil || !q.Versioned {
		t.Fatalf("honest versioned server: %+v %v", q, err)
	}
	c, _ := shareds3.New(cfg)
	if page, err := c.ListObjectVersions(ctx, "qualify/", shareds3.VersionCursor{}); err != nil || len(page.Objects) != 0 {
		t.Fatalf("qualification left %d objects: %v", len(page.Objects), err)
	}
	for lying, want := range map[string]string{"conditional": "exclusive create: a second", "replaced": "exclusive create: the refused PUT", "age": "age metadata: no LastModified", "erasure": "erasure:", "unsigned": "signatures: a request signed with a wrong secret"} {
		lie.Store(lying)
		if _, err := QualifyProvider(ctx, cfg, time.Now); err == nil || !strings.Contains(err.Error(), "qualify: "+want) {
			t.Errorf("a provider lying about %s: %v", lying, err)
		}
		lie.Store("")
		if err := c.DeletePrefix(ctx, "qualify/"); err != nil {
			t.Fatal(err)
		}
	}
	skewed := func() time.Time { return time.Now().Add(MaxProviderSkew + time.Minute) }
	if _, err := QualifyProvider(ctx, cfg, skewed); err == nil || !strings.Contains(err.Error(), "provider clock differs") {
		t.Errorf("a skewed clock qualified: %v", err)
	}
	wrong := cfg
	wrong.SecretKey = "not-the-secret"
	if _, err := QualifyProvider(ctx, wrong, time.Now); err == nil {
		t.Error("wrong credentials qualified")
	}
	if page, err := c.ListObjectVersions(ctx, "qualify/", shareds3.VersionCursor{}); err != nil || len(page.Objects) != 0 {
		t.Fatalf("a failed qualification left %d objects: %v", len(page.Objects), err)
	}
}
