package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedAssetsContainNoMergeConflictMarkers(t *testing.T) {
	markers := [][]byte{
		[]byte("<<<<<<<"),
		[]byte("======="),
		[]byte(">>>>>>>"),
	}

	err := fs.WalkDir(dist, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, readErr := fs.ReadFile(dist, path)
		if readErr != nil {
			return readErr
		}
		for _, marker := range markers {
			if bytes.Contains(body, marker) {
				t.Errorf("embedded asset %q contains merge-conflict marker %q", path, marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandlerServesAppAndSPAPaths(t *testing.T) {
	asset := ""
	_ = fs.WalkDir(dist, ".", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && strings.HasSuffix(path, ".js") {
			asset = "/" + strings.TrimPrefix(path, "dist/")
		}
		return nil
	})
	if asset == "" {
		t.Fatal("embedded JavaScript asset is missing")
	}
	for _, path := range []string{"/", asset} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		Handler().ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%q", path, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	res := httptest.NewRecorder()
	Handler().ServeHTTP(res, req)
	if res.Code != http.StatusNotFound || strings.Contains(res.Body.String(), "KyNotes") {
		t.Fatalf("missing path: status=%d body=%q", res.Code, res.Body.String())
	}
	if got := Handler(); got == nil {
		t.Fatal("handler is nil")
	}
}
