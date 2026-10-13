package applysetup

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

// Stage validates secret-free metadata and publishes only the product's dedicated
// installer bundle. Credential files are referenced, never created or overwritten here.
func Stage(dataDir, file string, raw []byte, allowPrivate, check bool) (string, error) {
	if len(raw) > MaxBundleBytes || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || file != filepath.Join(dataDir, "installer", "setup.json") {
		return "", errors.New("invalid setup preparation path or size")
	}
	var b bundle
	if decodeStrict(bytes.NewReader(raw), &b) != nil {
		return "", errors.New("invalid secret-free preparation metadata")
	}
	req := Request{Version: b.Version, Admins: b.Admins}
	paths := []string{}
	if s := b.SSO; s != nil {
		paths = append(paths, s.ClientSecretFile)
		if s.DirectoryHMACSecretFile != "" {
			paths = append(paths, s.DirectoryHMACSecretFile)
		}
		// Validate URLs/identity/backup intent without reading or inventing credentials.
		req.SSO = &SSO{IssuerURL: s.IssuerURL, ClientID: s.ClientID, RedirectURI: s.RedirectURI, ClientSecret: "metadata-validation"}
	}
	if bb := b.Backup; bb != nil {
		req.Backup = &Backup{Dir: bb.Dir, Keep: bb.Keep, DepositInterval: bb.DepositInterval}
		if rc := bb.Recovery; rc != nil {
			paths = append(paths, rc.PairingCodeFile)
			req.Backup.Recovery = &Recovery{URL: rc.URL, PairingCode: "000000"}
		}
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsFunc(path, unicode.IsControl) || path == file {
			return "", errors.New("preparation requires clean absolute credential paths distinct from the bundle")
		}
	}
	if req.Validate(allowPrivate) != nil {
		return "", errors.New("invalid setup preparation intent")
	}
	canonical, err := json.Marshal(b)
	if err != nil {
		return "", errors.New("cannot encode setup preparation")
	}
	// Validate the persistent anchor before creating anything beneath it. Existing
	// directories are never chmodded/adopted; keyfile.Store publishes without replacement.
	if requireSetupDirectory(dataDir, false) != nil {
		return "", errors.New("setup preparation requires a container-owned product data directory protected from other writers")
	}
	dir := filepath.Dir(file)
	if !check {
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errors.New("cannot create private installer directory")
		}
	}
	if requireSetupDirectory(dir, true) != nil {
		return "", errors.New("installer directory is missing, shared or not container-owned")
	}
	if check {
		return compareStaged(file, canonical)
	}
	if err := keyfile.Store(file, canonical, keyfile.Raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			return compareStaged(file, canonical)
		}
		return "", errors.New("cannot publish private installer bundle")
	}
	return "created", nil
}

func requireSetupDirectory(dir string, private bool) error {
	fd, err := openSetupParent(filepath.Join(dir, "setup.json"))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	mask := uint32(0022)
	if private {
		mask = 0077
	}
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&mask != 0 {
		return errors.New("setup directory must be private and owned by the container user")
	}
	return nil
}

func compareStaged(file string, canonical []byte) (string, error) {
	existing, err := readCapped(file, MaxBundleBytes)
	if err != nil || !bytes.Equal(existing, canonical) {
		return "", errors.New("prepared bundle is missing, unsafe or has different intent; existing files are preserved")
	}
	return "present", nil
}
