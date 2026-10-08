package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

const envelopeAlg = "x25519-hkdf-sha256-chacha20poly1305"

type client struct {
	base, user, password, config  string
	original, authSecret, keyPath string
	iterations                    int
	takenOver                     bool // the account holds a temporary password until restorePassword
	deviceKey                     *ecdh.PrivateKey
	server                        string
	hc                            *http.Client
	cookies                       []*http.Cookie
	csrf, containerID, objectID   string
	deviceID, deviceSecret        string
	attachmentID, previewUploadID string
	version                       int
	userID, loginSalt             string
	identityDevice                string
	identityKey                   *ecdh.PrivateKey // the account's identity, unwrapped with the password
	generation                    int64            // the probe notebook's key generation
	contentKey                    []byte           // the probe notebook's key at generation
}

func main() {
	base := flag.String("url", "http://127.0.0.1:8080", "server URL")
	user := flag.String("username", "", "username")
	password := flag.String("password", "", "password")
	config := flag.String("config", "/data/kynotes.yaml", "server config path")
	server := flag.String("server", "kynotes-server", "server binary for maintenance checks")
	keyPath := flag.String("device-key", "", "device private key file (default: user cache dir, per server URL and username)")
	flag.Parse()
	p := &client{base: strings.TrimRight(*base, "/"), user: *user, password: *password, original: *password, config: *config, server: *server, keyPath: *keyPath, hc: &http.Client{Timeout: 30 * time.Second}}
	if p.keyPath == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "device key: %v\n", err)
			os.Exit(1)
		}
		sum := sha256.Sum256([]byte(p.base + "\x00" + p.user))
		p.keyPath = filepath.Join(cache, "kynotes-probe", hex.EncodeToString(sum[:])+".key")
	}
	if err := p.recoverTakeOver(); err != nil {
		fmt.Fprintf(os.Stderr, "restore password from an interrupted run: %v\n", err)
		os.Exit(1)
	}
	// A password change revokes every device, so the take-over runs before pairing (inside
	// identity) and the restore after the device is revoked.
	steps := []func() error{p.login, p.identity, p.keyContainer, p.pair, p.envelope, p.selectContainer, p.saveAndRead, p.conflict, p.upload, p.dedup, p.download, p.preview, p.catchUp, p.deleteAndGC}
	for i, step := range steps {
		if err := step(); err != nil {
			fmt.Fprintf(os.Stderr, "step %d failed: %v\n", i+1, err)
			if p.deviceID != "" {
				_ = p.revokeDevice()
			}
			if err := p.restorePassword(); err != nil {
				fmt.Fprintf(os.Stderr, "restore password: %v; re-run the probe to retry\n", err)
			}
			os.Exit(1)
		}
		fmt.Printf("step %d ok\n", i+1)
	}
	if err := p.revokeDevice(); err != nil {
		fmt.Fprintf(os.Stderr, "revoke probe device: %v\n", err)
		_ = p.restorePassword()
		os.Exit(1)
	}
	fmt.Println("probe device revoked")
	if err := p.restorePassword(); err != nil {
		fmt.Fprintf(os.Stderr, "restore password: %v; re-run the probe to retry\n", err)
		os.Exit(1)
	}
}

func (p *client) takeOverPath() string { return p.keyPath + ".takeover" }

// identity makes sure the probe account holds a password-wrapped identity this run can use: it
// was unwrapped at login, or it is created now. If an administrator set the password, creating
// it is refused (409 password_change_required), and the password is taken over first, as a user
// would. An identity without a password copy cannot be used here and stops the run.
func (p *client) identity() error {
	if p.identityKey != nil {
		return nil
	}
	res, err := p.request(http.MethodGet, "/api/v1/me/identity", nil, nil, false)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return errors.New("the probe account has an encryption key without a password copy (an administrator reset); reset it in Settings or use a fresh account")
	}
	for attempt := 0; attempt < 2; attempt++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		kek, err := teamkeys.UserKEK(p.password, p.loginSalt, p.iterations)
		if err != nil {
			return err
		}
		wrapped, err := teamkeys.SealIdentity(kek, key.Bytes(), p.userID)
		if err != nil {
			return err
		}
		if err = p.stepUp(); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]string{"publicKey": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "wrapAlg": "aes-256-gcm", "wrappedPrivateKey": base64.StdEncoding.EncodeToString(wrapped)})
		res, err := p.request(http.MethodPut, "/api/v1/me/identity", body, nil, false)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusOK {
			var out struct {
				DeviceID string `json:"deviceId"`
			}
			if err = json.Unmarshal(b, &out); err != nil || out.DeviceID == "" {
				return fmt.Errorf("identity create: %s", b)
			}
			p.identityKey, p.identityDevice = key, out.DeviceID
			return nil
		}
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if attempt > 0 || res.StatusCode != http.StatusConflict || json.Unmarshal(b, &e) != nil || e.Error.Code != "password_change_required" {
			return fmt.Errorf("identity create: status %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
		}
		if err = p.takeOver(); err != nil {
			return err
		}
	}
	return errors.New("identity create: unreachable")
}

// takeOver replaces an operator-set password with a temporary one, as a user taking over the
// account would.
func (p *client) takeOver() error {
	temp := make([]byte, 24)
	if _, err := rand.Read(temp); err != nil {
		return err
	}
	// Written first, so a run that dies after the change can still restore the password.
	if err := os.MkdirAll(filepath.Dir(p.takeOverPath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p.takeOverPath(), []byte(hex.EncodeToString(temp)), 0o600); err != nil {
		return err
	}
	if err := p.changePassword(hex.EncodeToString(temp)); err != nil {
		return err
	}
	p.takenOver = true
	fmt.Println("operator-set password taken over")
	return nil
}

// keyContainer creates the probe's notebook and gives it its first key, as a browser does at
// creation: generation 1 holds nothing, and the first rotation makes generation 2 its first key.
func (p *client) keyContainer() error {
	res, err := p.request(http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","metaCiphertext":""}`), nil, false)
	if err != nil {
		return err
	}
	var container struct {
		ID string `json:"id"`
	}
	if err = decode(res, &container); err != nil {
		return err
	}
	p.containerID = container.ID
	p.contentKey = make([]byte, 32)
	if _, err = rand.Read(p.contentKey); err != nil {
		return err
	}
	sealed, err := teamkeys.SealEnvelope(p.contentKey, p.identityKey.PublicKey().Bytes(), p.containerID, 2, p.identityDevice, p.identityKey, p.identityDevice)
	if err != nil {
		return err
	}
	if err = p.stepUp(); err != nil {
		return err
	}
	body := []byte(fmt.Sprintf(`{"expectedGeneration":1,"envelopes":[{"deviceId":%q,"keyGeneration":2,"alg":%q,"envelope":%q}]}`, p.identityDevice, envelopeAlg, base64.StdEncoding.EncodeToString(sealed)))
	res, err = p.request(http.MethodPost, "/api/v1/containers/"+p.containerID+"/key-rotations", body, nil, false)
	if err != nil {
		return err
	}
	var rotated struct {
		KeyGeneration int64 `json:"keyGeneration"`
	}
	if err = decode(res, &rotated); err != nil {
		return err
	}
	if rotated.KeyGeneration != 2 {
		return fmt.Errorf("first key at generation %d, want 2", rotated.KeyGeneration)
	}
	p.generation = 2
	return nil
}

// restorePassword sets the original password back over the current session, which a password
// change keeps; the account then no longer counts as admin-known, so later runs skip the take-over.
func (p *client) restorePassword() error {
	if !p.takenOver {
		return nil
	}
	if err := p.changePassword(p.original); err != nil {
		return err
	}
	p.takenOver = false
	fmt.Println("original password restored")
	return os.Remove(p.takeOverPath())
}

// recoverTakeOver restores the password a previous run took over and never restored.
func (p *client) recoverTakeOver() error {
	temp, err := os.ReadFile(p.takeOverPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	p.password = string(temp)
	if err = p.login(); errors.Is(err, errInvalidCredentials) {
		// The change never committed.
		p.password = p.original
		return os.Remove(p.takeOverPath())
	}
	if err != nil {
		return err
	}
	p.takenOver = true
	return p.restorePassword()
}

// changePassword uses the user's own change route and re-wraps the probe identity under the new
// password in the same request.
func (p *client) changePassword(password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	loginSalt := base64.StdEncoding.EncodeToString(salt)
	secret, err := auth.DeriveAuthSecret(password, loginSalt, p.iterations)
	if err != nil {
		return err
	}
	in := map[string]any{"currentAuthSecret": p.authSecret, "newAuthSecret": secret, "newLoginSalt": loginSalt, "iterations": p.iterations}
	if p.identityKey != nil {
		kek, err := teamkeys.UserKEK(password, loginSalt, p.iterations)
		if err != nil {
			return err
		}
		wrapped, err := teamkeys.SealIdentity(kek, p.identityKey.Bytes(), p.userID)
		if err != nil {
			return err
		}
		in["identityDeviceId"], in["wrappedIdentityKey"] = p.identityDevice, base64.StdEncoding.EncodeToString(wrapped)
	}
	body, _ := json.Marshal(in)
	res, err := p.request(http.MethodPost, "/api/v1/auth/password", body, nil, false)
	if err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusNoContent); err != nil {
		return fmt.Errorf("password change: %w", err)
	}
	p.password, p.authSecret, p.loginSalt = password, secret, loginSalt
	return nil
}

func (p *client) stepUp() error {
	res, err := p.request(http.MethodPost, "/api/v1/auth/step-up", []byte(fmt.Sprintf(`{"authSecret":%q}`, p.authSecret)), nil, false)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("step-up status %d", res.StatusCode)
	}
	return nil
}

// loadOrCreateDeviceKey returns the probe's random X25519 device key, created
// once (0600, in a 0700 directory) so re-runs re-pair the same device.
func loadOrCreateDeviceKey(path string) (*ecdh.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("%s: mode %o, want 600", path, info.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ecdh.X25519().NewPrivateKey(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(key.Bytes()); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return key, nil
}

// revokeDevice logs in again (revocation needs a session under five minutes
// old) and revokes the probe device so no steward keeps wrapping keys to it.
func (p *client) revokeDevice() error {
	if err := p.login(); err != nil {
		return err
	}
	res, err := p.request(http.MethodDelete, "/api/v1/devices/"+p.deviceID, nil, nil, false)
	if err != nil {
		return err
	}
	return requireStatus(res, http.StatusNoContent)
}

func (p *client) request(method, path string, body []byte, headers map[string]string, device bool) (*http.Response, error) {
	req, err := http.NewRequest(method, p.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range p.cookies {
		req.AddCookie(c)
	}
	if p.csrf != "" {
		req.Header.Set("X-CSRF-Token", p.csrf)
	}
	if device {
		req.Header.Set("X-Kynotes-Device-Id", p.deviceID)
		req.Header.Set("X-Kynotes-Device-Secret", p.deviceSecret)
	} else {
		req.Header.Set("X-Kynotes-Key-Scheme", "shared-v2")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	for _, c := range res.Cookies() {
		if c.Name == "csrf_token" {
			p.csrf = c.Value
		}
		found := false
		for i := range p.cookies {
			if p.cookies[i].Name == c.Name {
				p.cookies[i] = c
				found = true
			}
		}
		if !found && (c.Name == "kynotes_session" || c.Name == "csrf_token") {
			p.cookies = append(p.cookies, c)
		}
	}
	return res, nil
}

func decode[T any](res *http.Response, out *T) error {
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("status %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func expect(res *http.Response, code int) ([]byte, error) {
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != code {
		return nil, fmt.Errorf("status %d, want %d: %s", res.StatusCode, code, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (p *client) login() error {
	res, err := p.request(http.MethodPost, "/api/v1/auth/login-params", []byte(`{"username":"`+p.user+`"}`), nil, false)
	if err != nil {
		return err
	}
	var params struct {
		LoginSalt  string `json:"loginSalt"`
		Iterations int    `json:"iterations"`
	}
	if err = decode(res, &params); err != nil {
		return err
	}
	p.iterations, p.loginSalt = params.Iterations, params.LoginSalt
	if p.authSecret, err = auth.DeriveAuthSecret(p.password, params.LoginSalt, params.Iterations); err != nil {
		return err
	}
	res, err = p.request(http.MethodPost, "/api/v1/auth/login", []byte(fmt.Sprintf(`{"username":%q,"authSecret":%q}`, p.user, p.authSecret)), nil, false)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusUnauthorized {
		res.Body.Close()
		return errInvalidCredentials
	}
	var session struct {
		User struct {
			ID          string `json:"id"`
			AccountKind string `json:"accountKind"`
		} `json:"user"`
		Identity *struct {
			DeviceID          string `json:"deviceId"`
			WrapAlg           string `json:"wrapAlg"`
			WrappedPrivateKey string `json:"wrappedPrivateKey"`
		} `json:"identity"`
	}
	if err = decode(res, &session); err != nil {
		return err
	}
	p.userID = session.User.ID
	if session.User.AccountKind != "user" {
		return errAdminAccount
	}
	p.identityKey, p.identityDevice = nil, ""
	if session.Identity == nil || session.Identity.WrapAlg != "aes-256-gcm" {
		return nil // none yet, or no password copy: identity() decides
	}
	kek, err := teamkeys.UserKEK(p.password, p.loginSalt, p.iterations)
	if err != nil {
		return err
	}
	wrapped, err := base64.StdEncoding.DecodeString(session.Identity.WrappedPrivateKey)
	if err != nil {
		return err
	}
	raw, err := teamkeys.OpenIdentity(kek, wrapped, p.userID)
	if err != nil {
		return fmt.Errorf("unwrap the probe identity: %w", err)
	}
	if p.identityKey, err = ecdh.X25519().NewPrivateKey(raw); err != nil {
		return err
	}
	p.identityDevice = session.Identity.DeviceID
	return nil
}

var errAdminAccount = errors.New("the probe account is an administrator account, which cannot open notes; use an everyday account (user add without --admin)")
var errInvalidCredentials = errors.New("login: invalid credentials")

func requireStatus(res *http.Response, code int) error {
	_, err := expect(res, code)
	return err
}

func (p *client) pair() error {
	res, err := p.request(http.MethodPost, "/api/v1/devices/pairing-token", nil, nil, false)
	if err != nil {
		return err
	}
	var token struct {
		Token string `json:"token"`
	}
	if err = decode(res, &token); err != nil {
		return err
	}
	if p.deviceKey, err = loadOrCreateDeviceKey(p.keyPath); err != nil {
		return err
	}
	publicKey := base64.StdEncoding.EncodeToString(p.deviceKey.PublicKey().Bytes())
	body := []byte(fmt.Sprintf(`{"pairingToken":%q,"publicKey":%q,"platform":"unknown","labelCiphertext":""}`, token.Token, publicKey))
	res, err = p.request(http.MethodPost, "/api/v1/devices/register", body, nil, false)
	if err != nil {
		return err
	}
	var device struct {
		ID     string `json:"deviceId"`
		Secret string `json:"deviceSecret"`
	}
	if err = decode(res, &device); err != nil {
		return err
	}
	p.deviceID, p.deviceSecret = device.ID, device.Secret
	if p.deviceID == "" || p.deviceSecret == "" {
		return errors.New("device registration returned no credential")
	}
	return nil
}

// envelope steps up, installs a real envelope for the paired device, proves the
// device opens it, and proves a second envelope for that recipient is refused.
func (p *client) envelope() error {
	if err := p.stepUp(); err != nil {
		return err
	}
	sealed, err := teamkeys.SealEnvelope(p.contentKey, p.deviceKey.PublicKey().Bytes(), p.containerID, uint32(p.generation), p.deviceID, p.identityKey, p.identityDevice)
	if err != nil {
		return err
	}
	body := []byte(fmt.Sprintf(`{"envelopes":[{"deviceId":%q,"keyGeneration":%d,"alg":%q,"envelope":%q}]}`, p.deviceID, p.generation, envelopeAlg, base64.StdEncoding.EncodeToString(sealed)))
	res, err := p.request(http.MethodPut, "/api/v1/containers/"+p.containerID+"/envelopes", body, nil, false)
	if err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusNoContent); err != nil {
		return err
	}
	if res, err = p.request(http.MethodPut, "/api/v1/containers/"+p.containerID+"/envelopes", body, nil, false); err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusConflict); err != nil {
		return fmt.Errorf("second envelope for one recipient: %w", err)
	}
	if res, err = p.request(http.MethodGet, "/api/v1/containers/"+p.containerID+"/envelopes", nil, nil, true); err != nil {
		return err
	}
	var envelopes []struct {
		Envelope string `json:"envelope"`
	}
	if err = decode(res, &envelopes); err != nil {
		return err
	}
	if len(envelopes) != 1 {
		return fmt.Errorf("device read returned %d envelopes", len(envelopes))
	}
	raw, err := base64.StdEncoding.DecodeString(envelopes[0].Envelope)
	if err != nil {
		return err
	}
	opened, err := teamkeys.OpenEnvelope(raw, p.deviceKey, p.containerID, uint32(p.generation), p.deviceID, p.identityKey.PublicKey().Bytes())
	if err != nil || !bytes.Equal(opened, p.contentKey) {
		return fmt.Errorf("device could not open its envelope: %v", err)
	}
	return nil
}

func (p *client) selectContainer() error {
	body, _ := json.Marshal([]string{p.containerID})
	res, err := p.request(http.MethodPut, "/api/v1/devices/"+p.deviceID+"/containers", body, nil, false)
	if err != nil {
		return err
	}
	return requireStatus(res, http.StatusNoContent)
}

func (p *client) createObject() error {
	res, err := p.request(http.MethodPost, "/api/v1/containers/"+p.containerID+"/objects", []byte(`{"kind":"note"}`), nil, false)
	if err != nil {
		return err
	}
	var object struct {
		ID string `json:"id"`
	}
	if err = decode(res, &object); err != nil {
		return err
	}
	p.objectID = object.ID
	return nil
}

func (p *client) save(body []byte, base int) (*http.Response, error) {
	return p.request(http.MethodPut, "/api/v1/objects/"+p.objectID, body, map[string]string{
		"Content-Type":             "application/octet-stream",
		"X-Kynotes-Base-Version":   fmt.Sprint(base),
		"X-Kynotes-Key-Generation": fmt.Sprint(p.generation),
	}, false)
}

func (p *client) saveAndRead() error {
	if err := p.createObject(); err != nil {
		return err
	}
	for version, body := range [][]byte{[]byte("probe-ciphertext-v1"), []byte("probe-ciphertext-v2")} {
		res, err := p.save(body, version)
		if err != nil {
			return err
		}
		if err = requireStatus(res, http.StatusOK); err != nil {
			return err
		}
	}
	for _, version := range []int{1, 2} {
		res, err := p.request(http.MethodGet, "/api/v1/objects/"+p.objectID+fmt.Sprintf("?version=%d", version), nil, nil, true)
		if err != nil {
			return err
		}
		b, err := expect(res, http.StatusOK)
		if err != nil || len(b) == 0 {
			return fmt.Errorf("read version %d: %w", version, err)
		}
	}
	p.version = 2
	return nil
}

func (p *client) conflict() error {
	res, err := p.save([]byte("stale-ciphertext"), 1)
	if err != nil {
		return err
	}
	b, err := expect(res, http.StatusConflict)
	if err != nil {
		return err
	}
	var v struct {
		ConflictID string `json:"conflictId"`
	}
	if json.Unmarshal(b, &v) != nil || v.ConflictID == "" {
		return errors.New("conflict response did not preserve conflict id")
	}
	res, err = p.request(http.MethodGet, "/api/v1/conflicts/"+v.ConflictID, nil, nil, true)
	if err != nil {
		return err
	}
	_, err = expect(res, http.StatusOK)
	return err
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (p *client) createUpload(kind string, data []byte) (string, error) {
	body := []byte(fmt.Sprintf(`{"declaredBytes":%d,"expectedDigest":%q,"kind":%q}`, len(data), digest(data), kind))
	res, err := p.request(http.MethodPost, "/api/v1/containers/"+p.containerID+"/uploads", body, nil, false)
	if err != nil {
		return "", err
	}
	var v struct {
		ID string `json:"uploadId"`
	}
	if err = decode(res, &v); err != nil {
		return "", err
	}
	return v.ID, nil
}

func (p *client) sendChunks(id string, data []byte, stopAfter int) error {
	const chunk = 4 * 1024 * 1024
	for index, offset := 0, 0; offset < len(data); index, offset = index+1, offset+chunk {
		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}
		if stopAfter >= 0 && index > stopAfter {
			break
		}
		res, err := p.request(http.MethodPatch, "/api/v1/uploads/"+id, data[offset:end], map[string]string{"X-Kynotes-Chunk-Index": fmt.Sprint(index), "Content-Type": "application/octet-stream"}, false)
		if err != nil {
			return err
		}
		if err = requireStatus(res, http.StatusOK); err != nil {
			return err
		}
	}
	return nil
}

func (p *client) finalizeUpload(id string, preview string) (map[string]any, error) {
	body := []byte(fmt.Sprintf(`{"metadataCiphertext":"","keyGeneration":%d,"previewUploadId":%q}`, p.generation, preview))
	res, err := p.request(http.MethodPost, "/api/v1/uploads/"+id+"/finalize", body, nil, false)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err = decode(res, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func (p *client) upload() error {
	data := bytes.Repeat([]byte("cipher"), 9*1024*1024/6)
	id, err := p.createUpload("attachment", data)
	if err != nil {
		return err
	}
	if err = p.sendChunks(id, data, 1); err != nil {
		return err
	}
	if err = p.sendChunksFrom(id, data, 2); err != nil {
		return err
	}
	v, err := p.finalizeUpload(id, "")
	if err != nil {
		return err
	}
	if _, ok := v["attachmentId"].(string); !ok {
		return errors.New("finalize returned no attachment")
	}
	p.attachmentID = v["attachmentId"].(string)
	return nil
}

func (p *client) sendChunksFrom(id string, data []byte, start int) error {
	const chunk = 4 * 1024 * 1024
	for index, offset := start, start*chunk; offset < len(data); index, offset = index+1, offset+chunk {
		end := offset + chunk
		if end > len(data) {
			end = len(data)
		}
		res, err := p.request(http.MethodPatch, "/api/v1/uploads/"+id, data[offset:end], map[string]string{"X-Kynotes-Chunk-Index": fmt.Sprint(index), "Content-Type": "application/octet-stream"}, false)
		if err != nil {
			return err
		}
		if err = requireStatus(res, http.StatusOK); err != nil {
			return err
		}
	}
	return nil
}

func (p *client) dedup() error {
	data := bytes.Repeat([]byte("cipher"), 9*1024*1024/6)
	id, err := p.createUpload("attachment", data)
	if err != nil {
		return err
	}
	if err = p.sendChunks(id, data, -1); err != nil {
		return err
	}
	v, err := p.finalizeUpload(id, "")
	if err != nil {
		return err
	}
	if v["attachmentId"] != p.attachmentID {
		return fmt.Errorf("dedup attachment %v != %s", v["attachmentId"], p.attachmentID)
	}
	return nil
}

func (p *client) download() error {
	res, err := p.request(http.MethodGet, "/api/v1/attachments/"+p.attachmentID, nil, nil, false)
	if err != nil {
		return err
	}
	if _, err = expect(res, http.StatusOK); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, p.base+"/api/v1/attachments/"+p.attachmentID, nil)
	if err != nil {
		return err
	}
	for _, c := range p.cookies {
		req.AddCookie(c)
	}
	req.Header.Set("Range", "bytes=0-15")
	res, err = p.hc.Do(req)
	if err != nil {
		return err
	}
	_, err = expect(res, http.StatusPartialContent)
	return err
}

func (p *client) preview() error {
	preview := []byte("preview-ciphertext")
	id, err := p.createUpload("preview", preview)
	if err != nil {
		return err
	}
	if err = p.sendChunks(id, preview, -1); err != nil {
		return err
	}
	if _, err = p.finalizeUpload(id, ""); err != nil {
		return err
	}
	mainData := []byte("image-ciphertext")
	mainID, err := p.createUpload("attachment", mainData)
	if err != nil {
		return err
	}
	if err = p.sendChunks(mainID, mainData, -1); err != nil {
		return err
	}
	// The preview finalize response is intentionally only a digest; the upload ID
	// is the reference carried by the main attachment finalize request.
	_, err = p.finalizeUpload(mainID, id)
	if err != nil {
		return err
	}
	return nil
}

func (p *client) catchUp() error {
	res, err := p.request(http.MethodGet, "/api/v1/containers/"+p.containerID+"/changes?since=0&limit=1", nil, nil, true)
	if err != nil {
		return err
	}
	var first struct {
		Next string `json:"nextCursor"`
	}
	if err = decode(res, &first); err != nil {
		return err
	}
	res, err = p.request(http.MethodPost, "/api/v1/containers/"+p.containerID+"/objects", []byte(`{"kind":"folder"}`), nil, false)
	if err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusOK); err != nil {
		return err
	}
	res, err = p.request(http.MethodGet, "/api/v1/containers/"+p.containerID+"/changes?since="+first.Next, nil, nil, true)
	if err != nil {
		return err
	}
	var changes struct {
		Changes []any `json:"changes"`
	}
	if err = decode(res, &changes); err != nil {
		return err
	}
	if len(changes.Changes) == 0 {
		return errors.New("offline catch-up returned no changes")
	}
	return nil
}

func (p *client) deleteAndGC() error {
	res, err := p.request(http.MethodDelete, "/api/v1/objects/"+p.objectID, nil, nil, false)
	if err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusNoContent); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		args := []string{"gc", "--now", "--retention", "0s", "--config", p.config}
		cmd := exec.Command(p.server, args...)
		if p.server == "docker" {
			cmd = exec.Command("docker", append([]string{"exec", "kynotes-probe-server", "/kynotes-server"}, args...)...)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("gc: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
