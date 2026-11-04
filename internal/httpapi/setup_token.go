package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// SetupTokenPath is the one-time first-run setup token: while no account exists, POST /setup
// needs it, so the first visitor of a fresh install cannot claim it. Setup deletes it.
func SetupTokenPath(dataDir string) string {
	return filepath.Join(dataDir, "secrets", "setup.token")
}

// EnsureSetupToken returns the setup token while the database has no account, minting it (0600)
// when absent and keeping an existing one so a restart does not void a copied token. Once any
// account exists it removes a leftover file and returns "".
func EnsureSetupToken(db *sql.DB, dataDir string) (string, error) {
	path := SetupTokenPath(dataDir)
	var users int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return "", err
	}
	if users > 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", nil
	}
	if token, err := readSetupToken(dataDir); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err = f.WriteString(token + "\n"); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return token, nil
}

func readSetupToken(dataDir string) (string, error) {
	raw, err := os.ReadFile(SetupTokenPath(dataDir))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 16 {
		return "", errors.New("setup token file is too short; delete it and restart to mint a new one")
	}
	return token, nil
}

// setupTokenMatches compares the presented token with the file in constant time.
func setupTokenMatches(dataDir, presented string) bool {
	want, err := readSetupToken(dataDir)
	return err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(presented))) == 1
}
