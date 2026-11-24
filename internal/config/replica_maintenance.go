package config

import (
	"errors"
	"os"
)

// LoadReplicaMaintenance reads configuration for explicit offline fingerprint acceptance.
// It never mints or reads local keys. Normal startup loaders retain their multi refusal.
func LoadReplicaMaintenance(path string) (Config, error) {
	if os.Getenv("KYNOTES_TENANCY") != "multi" {
		return Config{}, errors.New("replica maintenance requires KYNOTES_TENANCY=multi")
	}
	c, err := parseFile(path)
	if err != nil {
		return c, err
	}
	if err := applyEnvValues(&c); err != nil {
		return c, err
	}
	c.Secrets.PairingSecret = os.Getenv("KYNOTES_SECRETS_PAIRING_SECRET")
	c.Secrets.ServerSaltKey = os.Getenv("KYNOTES_SECRETS_SERVER_SALT_KEY")
	if len(c.Secrets.PairingSecret) < 32 || len(c.Secrets.ServerSaltKey) < 32 {
		return c, errors.New("replica maintenance requires retained pairing and server-salt keys in environment")
	}
	if c.Backup.BlobTarget.URL != "" {
		return c, errors.New("replica maintenance refuses the single-mode offsite mirror")
	}
	return c, validate(c, false)
}
