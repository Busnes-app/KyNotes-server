package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// dist is generated from web/ during the Docker build and checked in so local
// Go builds have the same embedded application as the release image.
//
//go:embed dist
var dist embed.FS

func Handler() http.Handler {
	files, _ := fs.Sub(dist, "dist")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		requested := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if requested == "." || requested == "" || strings.HasPrefix(requested, "share/") {
			requested = "index.html"
		}
		if _, err := fs.Stat(files, requested); err != nil {
			http.NotFound(w, r)
			return
		}
		body, err := fs.ReadFile(files, requested)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if contentType := mime.TypeByExtension(path.Ext(requested)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(body)
	})
}
