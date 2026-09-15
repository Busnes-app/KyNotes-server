package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Busness-app/kynotes-server/internal/ids"
	"github.com/Busness-app/kynotes-server/internal/logging"
	"github.com/Busness-app/kynotes-server/internal/reqid"
)

func Middleware(log *logging.Logger, max int64) func(http.Handler) http.Handler {
	return MiddlewareWithProxies(log, max, nil)
}
func MiddlewareWithProxies(log *logging.Logger, max int64, proxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := ""
			if ip := remoteIP(r); trusted(ip, proxies) {
				id = r.Header.Get("X-Request-Id")
			}
			if id == "" {
				id, _ = ids.Mint("req")
			}
			ctx := reqid.With(r.Context(), id)
			w.Header().Set("X-Request-Id", id)
			w = &responseWriter{ResponseWriter: w}
			rw := w.(*responseWriter)
			defer func() {
				if v := recover(); v != nil {
					log.Error("panic", "request_id", id, "error_kind", "panic")
					WriteError(rw, r, 500, "internal", "internal server error")
					_ = debug.Stack()
				}
			}()
			ciphertextBody := (r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v1/uploads/")) || (r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/objects/"))
			if max > 0 && r.Body != nil && !ciphertextBody {
				if r.ContentLength > max {
					WriteError(rw, r, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large")
					return
				}
				r.Body = http.MaxBytesReader(rw, r.Body, max)
			}
			r2 := r.WithContext(ctx)
			next.ServeHTTP(rw, r2)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *responseWriter) WriteHeader(s int) {
	if w.status != 0 {
		return
	}
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, e := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, e
}
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
func AccessLog(log *logging.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := w.(*responseWriter)
		next.ServeHTTP(rw, r)
		log.Info("request", "request_id", RequestID(r), "route", r.Pattern, "method", r.Method, "status", rw.status, "bytes", rw.bytes, "duration_ms", time.Since(start).Milliseconds())
	})
}
func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func bodyLimitError(err error) bool                   { return err != nil && fmt.Sprint(err) != "" }
func remoteIP(r *http.Request) net.IP {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
func trusted(ip net.IP, proxies []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range proxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
