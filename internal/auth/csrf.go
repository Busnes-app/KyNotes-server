package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sync/atomic"
)

// csrfKey signs CSRF tokens. Until SetCSRFKey runs it is a random per-process key, so a
// server that never sets one still refuses forged tokens; it just loses them on restart.
var csrfKey atomic.Pointer[[]byte]

func init() {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	csrfKey.Store(&k)
}

// SetCSRFKey derives the CSRF key from the server's pairing secret, so tokens survive a
// restart. The label keeps it apart from pairing MACs, which only ever sign JSON objects.
// A secret too short to be one is ignored and the random key stays.
func SetCSRFKey(secret string) {
	if len(secret) < 32 {
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("kynotes-csrf-key-v1"))
	k := mac.Sum(nil)
	csrfKey.Store(&k)
}

// CSRFToken is bound to one session: an HMAC of its session token under the server key.
// Only a page that holds that session's cookies can know it, so a token tossed in from a
// sibling origin, or copied from another session, does not verify.
func CSRFToken(rawSession string) string {
	mac := hmac.New(sha256.New, *csrfKey.Load())
	mac.Write([]byte("kynotes-csrf:" + rawSession))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CheckCSRF compares the X-CSRF-Token header, in constant time, with the token recomputed
// from the session cookie. The csrf_token cookie is only how the web app learns the value;
// it is never trusted. A request without a session cookie is not a session request and has
// nothing to forge: the route's session check refuses it.
func CheckCSRF(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	header := r.Header.Get("X-CSRF-Token")
	if c.Value == "" || header == "" || !hmac.Equal([]byte(header), []byte(CSRFToken(c.Value))) {
		return errors.New("csrf")
	}
	return nil
}

// RefreshCSRFCookie rewrites the csrf_token cookie for the presented session: a session
// minted before tokens were bound still holds a random value the server no longer accepts.
func RefreshCSRFCookie(w http.ResponseWriter, r *http.Request, insecure bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: CSRFToken(c.Value), Path: "/", HttpOnly: false, Secure: !insecure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 60 * 60})
}
