package applysetup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

type clientCredentials struct {
	Schema          string   `json:"schema"`
	SetupID         string   `json:"setupId"`
	IssuerURL       string   `json:"issuerUrl"`
	ClientID        string   `json:"clientId"`
	RedirectURIs    []string `json:"redirectUris"`
	DirectoryURL    string   `json:"directoryUrl,omitempty"`
	ClientSecret    string   `json:"clientSecret"`
	DirectorySecret string   `json:"directorySecret,omitempty"`
	Administrator   struct {
		Subject  string `json:"subject"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"administrator"`
}

var importSetupID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ImportClient copies one verified source client's credentials into the reserved
// prepared bundle's private files. It does not configure SSO, accounts or grants.
func ImportClient(dataDir, file string, raw []byte, allowPrivate, check bool) (string, error) {
	if len(raw) > MaxBundleBytes {
		return "", errors.New("private client frame exceeds its limit")
	}
	var frame clientCredentials
	if decodeStrict(bytes.NewReader(raw), &frame) != nil || frame.Schema != "kyidentity.client-credentials/1" || !importSetupID.MatchString(frame.SetupID) {
		return "", errors.New("invalid private client frame")
	}
	metadata, err := readCapped(file, MaxBundleBytes)
	if err != nil {
		return "", errors.New("client import requires a retained protected bundle")
	}
	if _, err := Stage(dataDir, file, metadata, allowPrivate, true); err != nil {
		return "", err
	}
	var b bundle
	if decodeStrict(bytes.NewReader(metadata), &b) != nil || b.SSO == nil || len(b.Admins) != 1 {
		return "", errors.New("client import requires SSO and one dedicated owner grant")
	}
	s, owner := b.SSO, b.Admins[0]
	if frame.IssuerURL != s.IssuerURL || frame.ClientID != s.ClientID || frame.Administrator.Role != "kynotes.admin" || owner.Issuer != frame.IssuerURL || owner.Subject != frame.Administrator.Subject || owner.Username != frame.Administrator.Username {
		return "", errors.New("client import does not match the prepared issuer, client or owner grant")
	}
	callback := false
	if len(frame.RedirectURIs) == 0 || len(frame.RedirectURIs) > 16 {
		return "", errors.New("invalid client callback list")
	}
	for _, uri := range frame.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(uri) > 2048 {
			return "", errors.New("invalid client callback")
		}
		callback = callback || uri == s.RedirectURI
	}
	if !callback || !importSecret(frame.ClientSecret) {
		return "", errors.New("client import callback or credential does not match")
	}
	dir := filepath.Dir(file)
	files := []struct{ path, value string }{{s.ClientSecretFile, frame.ClientSecret}}
	if s.ClientSecretFile != filepath.Join(dir, "client.secret") {
		return "", errors.New("client import requires its reserved credential path")
	}
	if s.DirectoryHMACSecretFile != "" {
		u, _ := url.Parse(s.RedirectURI) // Stage already validated the destination.
		if s.DirectoryHMACSecretFile != filepath.Join(dir, "directory.secret") || frame.DirectoryURL != "https://"+u.Host+"/api/v1/sync/events" || !importSecret(frame.DirectorySecret) {
			return "", errors.New("client import directory endpoint or credential does not match")
		}
		files = append(files, struct{ path, value string }{s.DirectoryHMACSecretFile, frame.DirectorySecret})
	} else if frame.DirectoryURL != "" || frame.DirectorySecret != "" {
		return "", errors.New("client import has an unselected directory connection")
	}
	canonical, _ := json.Marshal(frame)
	frameDigest, bundleDigest := sha256.Sum256(canonical), sha256.Sum256(metadata)
	receipt, _ := json.Marshal(struct {
		Schema       string `json:"schema"`
		ClientDigest string `json:"clientDigest"`
		BundleDigest string `json:"bundleDigest"`
	}{"kynotes.client-import/1", hex.EncodeToString(frameDigest[:]), hex.EncodeToString(bundleDigest[:])})
	receiptFile := filepath.Join(dir, "client-import.json")
	retained, err := importFilePresent(receiptFile, receipt)
	if err != nil {
		return "", err
	}
	missing := []int{}
	for i, f := range files {
		present, err := importFilePresent(f.path, []byte(f.value))
		if err != nil || present && !retained {
			return "", errors.New("client import refuses changed, unsafe or unowned credentials")
		}
		if !present {
			missing = append(missing, i)
		}
	}
	if check {
		if !retained || len(missing) != 0 {
			return "", errors.New("client import is not present")
		}
		return "present", nil
	}
	// Pin the exact source/bundle before copying bytes. Interrupted publication can
	// resume only the identical transfer; never invent or rotate a secret here.
	if !retained {
		if err := publishImportFile(receiptFile, receipt); err != nil {
			return "", err
		}
	}
	for _, i := range missing {
		if err := publishImportFile(files[i].path, []byte(files[i].value)); err != nil {
			return "", err
		}
	}
	if !retained || len(missing) != 0 {
		return "created", nil
	}
	return "present", nil
}

func importSecret(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func importFilePresent(file string, expected []byte) (bool, error) {
	if _, err := os.Lstat(file); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	retained, err := readCapped(file, MaxBundleBytes)
	if err != nil || !bytes.Equal(retained, expected) {
		return false, errors.New("client import file is unsafe or differs; existing files are preserved")
	}
	return true, nil
}

func publishImportFile(file string, value []byte) error {
	if err := keyfile.Store(file, value, keyfile.Raw); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errors.New("cannot publish protected client import file")
		}
		present, err := importFilePresent(file, value)
		if err != nil || !present {
			return errors.New("client import publication was not retained")
		}
	}
	return nil
}
