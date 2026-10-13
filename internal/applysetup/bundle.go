package applysetup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// readCapped opens every path component without following links. Validate the opened
// descriptors, rather than checking a path and then reopening a potentially replaced file.
func readCapped(path string, max int64) ([]byte, error) {
	dir, err := openSetupParent(path)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dir)
	fd, err := syscall.Openat(dir, filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open protected setup file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("setup files must be regular and private")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("setup files must belong to the container user")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, errors.New("cannot read protected setup file")
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return raw, nil
}

// openSetupParent returns an owned descriptor for a protected parent, even if the
// final file is absent. Callers close it; no untrusted user may replace its path.
func openSetupParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("want a clean absolute container-local path")
	}
	dir, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("cannot open protected setup directory")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(dir, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			syscall.Close(dir)
			return -1, errors.New("cannot open protected setup directory")
		}
		syscall.Close(dir)
		dir = next
		var st syscall.Stat_t
		if syscall.Fstat(dir, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0) {
			syscall.Close(dir)
			return -1, errors.New("setup directories must be owned by root or the container user and protected from other writers")
		}
	}
	return dir, nil
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
