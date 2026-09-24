package httpapi

import (
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/logging"
)

func TestProductIconsReachEmbeddedFiles(t *testing.T) {
	handler := NewRouter(logging.New(io.Discard, "info", "json"), 1<<20, func() bool { return true })
	for path, size := range map[string]int{"/favicon.png": 32, "/app-icon.png": 256, "/app-icon-192.png": 192, "/app-icon-512.png": 512} {
		t.Run(path, func(t *testing.T) {
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
			if res.Code != http.StatusOK {
				t.Fatalf("GET %s = %d", path, res.Code)
			}
			if res.Header().Get("Content-Type") != "image/png" {
				t.Fatalf("wrong content type: %s", res.Header().Get("Content-Type"))
			}
			img, err := png.DecodeConfig(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if img.Width != size || img.Height != size {
				t.Fatalf("got %dx%d, want %dx%d", img.Width, img.Height, size, size)
			}
		})
	}
}
