package applysetup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// bundle is the file the installer writes. Secrets appear only as paths; an inline secret
// field is unknown and rejected.
type bundle struct {
	Version int `json:"version"`
	SSO     *struct {
		IssuerURL               string `json:"issuerUrl"`
		ClientID                string `json:"clientId"`
		ClientSecretFile        string `json:"clientSecretFile"`
		RedirectURI             string `json:"redirectUri"`
		DirectoryHMACSecretFile string `json:"directoryHmacSecretFile"`
	} `json:"sso"`
	Admins []Admin `json:"admins"`
	Backup *struct {
		Dir             string `json:"dir"`
		Keep            int    `json:"keep"`
		DepositInterval string `json:"depositInterval"`
		Recovery        *struct {
			URL             string `json:"url"`
			PairingCodeFile string `json:"pairingCodeFile"`
		} `json:"recovery"`
	} `json:"backup"`
}

// Load reads and validates a bundle and the secret files it names.
func Load(path string, allowPrivate bool) (Request, error) {
	raw, err := readCapped(path, MaxBundleBytes)
	if err != nil {
		return Request{}, fmt.Errorf("bundle: %w", err)
	}
	var b bundle
	if err := decodeStrict(bytes.NewReader(raw), &b); err != nil {
		return Request{}, err
	}
	req := Request{Version: b.Version, Admins: b.Admins}
	if s := b.SSO; s != nil {
		secret, err := readSecret("sso.clientSecretFile", s.ClientSecretFile)
		if err != nil {
			return Request{}, err
		}
		var hmac string
		if s.DirectoryHMACSecretFile != "" {
			if hmac, err = readSecret("sso.directoryHmacSecretFile", s.DirectoryHMACSecretFile); err != nil {
				return Request{}, err
			}
		}
		req.SSO = &SSO{IssuerURL: s.IssuerURL, ClientID: s.ClientID, ClientSecret: secret, RedirectURI: s.RedirectURI, HMACSecret: hmac}
	}
	if bb := b.Backup; bb != nil {
		req.Backup = &Backup{Dir: bb.Dir, Keep: bb.Keep, DepositInterval: bb.DepositInterval}
		if rc := bb.Recovery; rc != nil {
			code, err := readSecret("backup.recovery.pairingCodeFile", rc.PairingCodeFile)
			if err != nil {
				return Request{}, err
			}
			req.Backup.Recovery = &Recovery{URL: rc.URL, PairingCode: code}
		}
	}
	return req, req.Validate(allowPrivate)
}

// readCapped refuses anything but a regular file (a FIFO would block the open) and
// anything larger than max.
func readCapped(path string, max int64) ([]byte, error) {
	if st, err := os.Stat(path); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return raw, nil
}

// readSecret names the field, never the content, in every error.
func readSecret(field, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: want an absolute path inside the container", field)
	}
	raw, err := readCapped(path, MaxSecretBytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	v := strings.TrimRight(string(raw), "\r\n")
	if !secretOK(v) {
		return "", fmt.Errorf("%s: empty or contains control characters", field)
	}
	return v, nil
}
