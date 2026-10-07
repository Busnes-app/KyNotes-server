// Package applysetup is the apply-setup contract: the installer's bundle, the request the
// CLI sends over the admin socket, the per-section decisions and the report.
package applysetup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
)

const (
	Version        = 1
	MaxBundleBytes = 64 << 10
	MaxSecretBytes = 4 << 10
	MaxAdmins      = 16
	CallbackPath   = "/api/v1/auth/oidc/callback"
	Actor          = "system"
	RequestID      = "apply-setup"
)

// Request is the bundle with every secret file already read. It travels only over the
// admin socket and is never logged or echoed.
type Request struct {
	Version int     `json:"version"`
	SSO     *SSO    `json:"sso,omitempty"`
	Admins  []Admin `json:"admins,omitempty"`
	Backup  *Backup `json:"backup,omitempty"`
}

type SSO struct {
	IssuerURL    string `json:"issuerUrl"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectUri"`
	HMACSecret   string `json:"hmacSecret,omitempty"`
}

type Admin struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Username string `json:"username"`
}

type Backup struct {
	Dir             string    `json:"dir,omitempty"`
	Keep            int       `json:"keep,omitempty"`
	DepositInterval string    `json:"depositInterval,omitempty"`
	Recovery        *Recovery `json:"recovery,omitempty"`
}

type Recovery struct {
	URL         string `json:"url"`
	PairingCode string `json:"pairingCode"`
}

// DecodeRequest is the server-side boundary: strict JSON, then the same validation the CLI ran.
func DecodeRequest(r io.Reader, allowPrivate bool) (Request, error) {
	var req Request
	if err := decodeStrict(r, &req); err != nil {
		return Request{}, err
	}
	return req, req.Validate(allowPrivate)
}

func decodeStrict(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("bundle: trailing data after the JSON object")
	}
	return nil
}

func (r Request) Validate(allowPrivate bool) error {
	if r.Version != Version {
		return fmt.Errorf("version: want %d", Version)
	}
	if r.SSO != nil {
		if err := r.SSO.validate(allowPrivate); err != nil {
			return err
		}
	}
	if len(r.Admins) > MaxAdmins {
		return fmt.Errorf("admins: at most %d", MaxAdmins)
	}
	subjects, names := map[[2]string]bool{}, map[string]bool{}
	for i, a := range r.Admins {
		if err := checkURL(fmt.Sprintf("admins[%d].issuer", i), a.Issuer, allowPrivate); err != nil {
			return err
		}
		if r.SSO != nil && a.Issuer != r.SSO.IssuerURL {
			return fmt.Errorf("admins[%d].issuer: must equal sso.issuerUrl", i)
		}
		if !Identifier(a.Subject) || !Identifier(a.Username) {
			return fmt.Errorf("admins[%d]: subject and username must be 1-256 bytes without surrounding space or control characters", i)
		}
		key, name := [2]string{a.Issuer, a.Subject}, strings.ToLower(a.Username)
		if subjects[key] || names[name] {
			return fmt.Errorf("admins[%d]: duplicate identity or username", i)
		}
		subjects[key], names[name] = true, true
	}
	if r.Backup != nil {
		return r.Backup.validate(allowPrivate)
	}
	return nil
}

func (s SSO) validate(allowPrivate bool) error {
	if err := checkURL("sso.issuerUrl", s.IssuerURL, allowPrivate); err != nil {
		return err
	}
	if err := checkURL("sso.redirectUri", s.RedirectURI, allowPrivate); err != nil {
		return err
	}
	if u, _ := url.Parse(s.RedirectURI); u.Path != CallbackPath {
		return fmt.Errorf("sso.redirectUri: path must be %s", CallbackPath)
	}
	if !Identifier(s.ClientID) {
		return errors.New("sso.clientId: must be 1-256 bytes without surrounding space or control characters")
	}
	if !secretOK(s.ClientSecret) {
		return errors.New("sso client secret: empty, over 4 KiB, or contains control characters")
	}
	if s.HMACSecret != "" && !secretOK(s.HMACSecret) {
		return errors.New("sso directory HMAC secret: over 4 KiB or contains control characters")
	}
	return nil
}

func (b Backup) validate(allowPrivate bool) error {
	if b.Dir != "" && !filepath.IsAbs(b.Dir) {
		return errors.New("backup.dir: want an absolute path")
	}
	if b.Keep < 0 {
		return errors.New("backup.keep: want a positive integer")
	}
	if b.DepositInterval != "" {
		if _, err := IntervalSeconds(b.DepositInterval); err != nil {
			return err
		}
	}
	if rc := b.Recovery; rc != nil {
		if err := checkURL("backup.recovery.url", rc.URL, allowPrivate); err != nil {
			return err
		}
		if len(rc.PairingCode) != 6 || strings.Trim(rc.PairingCode, "0123456789") != "" {
			return errors.New("backup.recovery pairing code: want six digits")
		}
	}
	return nil
}

// IntervalSeconds applies the recovery client's schedule bound: 0 (off) or
// MinInterval..MaxInterval in whole seconds.
func IntervalSeconds(raw string) (int64, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || d%time.Second != 0 || (d != 0 && (d < recoveryclient.MinInterval || d > recoveryclient.MaxInterval)) {
		return 0, fmt.Errorf("backup.depositInterval: 0 (off) or %s through %s in whole seconds", recoveryclient.MinInterval, recoveryclient.MaxInterval)
	}
	return int64(d / time.Second), nil
}

// Identifier is the account-name rule shared with directory provisioning.
func Identifier(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

func secretOK(s string) bool {
	return s != "" && len(s) <= MaxSecretBytes && !strings.ContainsFunc(s, unicode.IsControl)
}

func checkURL(field, raw string, allowPrivate bool) error {
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("%s: surrounding whitespace", field)
	}
	if err := recoveryclient.ValidateURL(raw, allowPrivate); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}
