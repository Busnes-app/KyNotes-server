package main

import (
	"bytes"
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
	"strings"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

const envelopeAlg = "x25519-hkdf-sha256-chacha20poly1305"

type client struct {
	base, user, password, config  string
	server                        string
	hc                            *http.Client
	cookies                       []*http.Cookie
	csrf, containerID, objectID   string
	deviceID, deviceSecret        string
	attachmentID, previewUploadID string
	version                       int
}

func main() {
	base := flag.String("url", "http://127.0.0.1:8080", "server URL")
	user := flag.String("username", "", "username")
	password := flag.String("password", "", "password")
	config := flag.String("config", "/data/kynotes.yaml", "server config path")
	server := flag.String("server", "kynotes-server", "server binary for maintenance checks")
	flag.Parse()
	p := &client{base: strings.TrimRight(*base, "/"), user: *user, password: *password, config: *config, server: *server, hc: &http.Client{Timeout: 30 * time.Second}}
	steps := []func() error{p.login, p.pair, p.envelope, p.selectContainer, p.saveAndRead, p.conflict, p.upload, p.dedup, p.download, p.preview, p.catchUp, p.deleteAndGC}
	for i, step := range steps {
		if err := step(); err != nil {
			fmt.Fprintf(os.Stderr, "step %d failed: %v\n", i+1, err)
			os.Exit(1)
		}
		fmt.Printf("step %d ok\n", i+1)
	}
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
	secret, err := auth.DeriveAuthSecret(p.password, params.LoginSalt, params.Iterations)
	if err != nil {
		return err
	}
	res, err = p.request(http.MethodPost, "/api/v1/auth/login", []byte(fmt.Sprintf(`{"username":%q,"authSecret":%q}`, p.user, secret)), nil, false)
	if err != nil {
		return err
	}
	return requireStatus(res, http.StatusOK)
}

func requireStatus(res *http.Response, code int) error {
	_, err := expect(res, code)
	return err
}

func (p *client) pair() error {
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
	res, err = p.request(http.MethodPost, "/api/v1/devices/pairing-token", nil, nil, false)
	if err != nil {
		return err
	}
	var token struct {
		Token string `json:"token"`
	}
	if err = decode(res, &token); err != nil {
		return err
	}
	publicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
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

func (p *client) envelope() error {
	body := []byte(fmt.Sprintf(`{"envelopes":[{"deviceId":%q,"keyGeneration":1,"alg":%q,"envelope":%q}]}`, p.deviceID, envelopeAlg, base64.StdEncoding.EncodeToString([]byte("encrypted-envelope"))))
	res, err := p.request(http.MethodPut, "/api/v1/containers/"+p.containerID+"/envelopes", body, nil, false)
	if err != nil {
		return err
	}
	if err = requireStatus(res, http.StatusNoContent); err != nil {
		return err
	}
	res, err = p.request(http.MethodGet, "/api/v1/containers/"+p.containerID+"/envelopes", nil, nil, true)
	if err != nil {
		return err
	}
	var envelopes []map[string]any
	if err = decode(res, &envelopes); err != nil {
		return err
	}
	if len(envelopes) != 1 {
		return fmt.Errorf("device read returned %d envelopes", len(envelopes))
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
		"X-Kynotes-Key-Generation": "1",
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
	body := []byte(fmt.Sprintf(`{"metadataCiphertext":"","keyGeneration":1,"previewUploadId":%q}`, preview))
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
