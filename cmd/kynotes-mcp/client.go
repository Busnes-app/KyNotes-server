package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

// maxBody caps what the bridge reads from one response.
// ponytail: fixed; the server's own limits.max_object_bytes is not visible to clients.
const maxBody = 64 << 20

// apiError is a non-2xx answer; code is the server's error code.
type apiError struct {
	status     int
	code       string
	conflictID string
}

func (e *apiError) Error() string { return fmt.Sprintf("server answered %d %s", e.status, e.code) }

var (
	errAdminAccount   = errors.New("this is an administrator account, which cannot open notes; use an everyday account")
	errPasswordChange = errors.New("an administrator set this account's password; sign in to KyNotes once as this account and choose a new one")
	errNoIdentity     = errors.New("this account has no encryption key yet; sign in to the KyNotes web app once as this account")
	errNoPasswordCopy = errors.New("this account's encryption key has no password copy (an administrator reset); sign in to the web app as this account and restore it")
)

// client is one signed-in everyday account and its unwrapped identity.
type client struct {
	base, username, password string
	hc                       *http.Client
	userID, identityDevice   string
	identity                 *ecdh.PrivateKey
}

func newClient(base, username, password string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{base: base, username: username, password: password, hc: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// login signs in with the password-derived auth secret and unwraps the identity, as the probe does.
func (c *client) login(ctx context.Context) error {
	var params struct {
		LoginSalt  string `json:"loginSalt"`
		Iterations int    `json:"iterations"`
	}
	if err := c.call(ctx, http.MethodPost, "/api/v1/auth/login-params", map[string]string{"username": c.username}, &params, false); err != nil {
		return err
	}
	secret, err := auth.DeriveAuthSecret(c.password, params.LoginSalt, params.Iterations)
	if err != nil {
		return err
	}
	var session struct {
		User struct {
			ID          string `json:"id"`
			AccountKind string `json:"accountKind"`
		} `json:"user"`
		PasswordChangeRequired bool `json:"passwordChangeRequired"`
		Identity               *struct {
			DeviceID          string `json:"deviceId"`
			WrapAlg           string `json:"wrapAlg"`
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
		} `json:"identity"`
	}
	if err := c.call(ctx, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": c.username, "authSecret": secret}, &session, false); err != nil {
		var api *apiError
		if errors.As(err, &api) && api.status == http.StatusUnauthorized {
			return errors.New("sign-in refused: wrong username or password, or the account is disabled")
		}
		return err
	}
	switch {
	case session.User.AccountKind != "user":
		return errAdminAccount
	case session.PasswordChangeRequired:
		return errPasswordChange
	case session.Identity == nil:
		return errNoIdentity
	case session.Identity.WrapAlg != "aes-256-gcm":
		return errNoPasswordCopy
	}
	kek, err := teamkeys.UserKEK(c.password, params.LoginSalt, params.Iterations)
	if err != nil {
		return err
	}
	wrapped, err := base64.StdEncoding.DecodeString(session.Identity.WrappedPrivateKey)
	if err != nil {
		return err
	}
	raw, err := teamkeys.OpenIdentity(kek, wrapped, session.User.ID)
	if err != nil {
		return fmt.Errorf("unwrap this account's encryption key: %w", err)
	}
	if c.identity, err = ecdh.X25519().NewPrivateKey(raw); err != nil {
		return err
	}
	c.userID, c.identityDevice = session.User.ID, session.Identity.DeviceID
	return nil
}

// do sends one request with the session cookie, CSRF token and current key scheme. A 401 signs
// in again and retries once.
func (c *client) do(ctx context.Context, method, path string, body []byte, headers map[string]string, relogin bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kynotes-Key-Scheme", "shared-v2")
	if u, err := url.Parse(c.base); err == nil {
		for _, ck := range c.hc.Jar.Cookies(u) {
			if ck.Name == "csrf_token" {
				req.Header.Set("X-CSRF-Token", ck.Value)
			}
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized && relogin {
		res.Body.Close()
		if err := c.login(ctx); err != nil {
			return nil, err
		}
		return c.do(ctx, method, path, body, headers, false)
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
			ConflictID string `json:"conflictId"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&e)
		if e.Error.Code == "password_change_required" {
			return nil, errPasswordChange
		}
		return nil, &apiError{status: res.StatusCode, code: e.Error.Code, conflictID: e.ConflictID}
	}
	return res, nil
}

// call sends in as JSON (nil for none) and decodes the answer into out (nil to discard).
func (c *client) call(ctx context.Context, method, path string, in, out any, relogin bool) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	res, err := c.do(ctx, method, path, body, nil, relogin)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(out)
}

// readObject returns an object's current ciphertext, version and key generation.
func (c *client) readObject(ctx context.Context, id string) (body []byte, version, generation int64, err error) {
	res, err := c.do(ctx, http.MethodGet, "/api/v1/objects/"+id, nil, nil, true)
	if err != nil {
		return nil, 0, 0, err
	}
	defer res.Body.Close()
	if body, err = io.ReadAll(io.LimitReader(res.Body, maxBody)); err != nil {
		return nil, 0, 0, err
	}
	if _, err = fmt.Sscan(res.Header.Get("X-Kynotes-Version"), &version); err != nil {
		return nil, 0, 0, errors.New("server sent no object version")
	}
	// A missing generation stays 0, which no key opens.
	_, _ = fmt.Sscan(res.Header.Get("X-Kynotes-Key-Generation"), &generation)
	return body, version, generation, nil
}

// saveObject writes sealed as the version after base at generation.
func (c *client) saveObject(ctx context.Context, id string, sealed []byte, base, generation int64) error {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	res, err := c.do(ctx, http.MethodPut, "/api/v1/objects/"+id, sealed, map[string]string{
		"Content-Type":             "application/octet-stream",
		"X-Kynotes-Base-Version":   fmt.Sprint(base),
		"X-Kynotes-Key-Generation": fmt.Sprint(generation),
		"Idempotency-Key":          hex.EncodeToString(key),
	}, true)
	if err != nil {
		return err
	}
	return res.Body.Close()
}

// fingerprint is the browser's: SHA-256 of the public key, hex in groups of four.
func fingerprint(publicKey []byte) string {
	sum := sha256Sum(publicKey)
	h := hex.EncodeToString(sum[:])
	var groups []string
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}
