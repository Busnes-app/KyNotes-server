package config

import (
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/Busnes-app/ky-primitives/offsite"
)

type BlobTarget struct {
	URL        string `yaml:"url"`
	AccessKey  string `yaml:"access_key"`
	Secret     string `yaml:"secret"`
	HostKey    string `yaml:"host_key"`
	S3Endpoint string `yaml:"s3_endpoint"`
	S3Region   string `yaml:"s3_region"`
}

func (c BlobTarget) Offsite() offsite.Config {
	return offsite.Config{URL: c.URL, AccessKey: c.AccessKey, Secret: c.Secret, HostKey: c.HostKey, S3Endpoint: c.S3Endpoint, S3Region: c.S3Region}
}
func ValidateBlobTarget(c BlobTarget) error {
	if c.URL == "" {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return errors.New("backup.blob_target: invalid URL")
	}
	if strings.EqualFold(u.Scheme, "sftp") && c.HostKey == "" {
		return errors.New("backup.blob_target: SFTP requires a verified SHA256 host key fingerprint")
	}
	if _, err := offsite.Parse(c.Offsite()); err != nil {
		return errors.New("backup.blob_target: invalid target or missing credentials; use file, S3, pinned SFTP or SMB with separate credential fields")
	}
	return nil
}
func applyBlobEnv(c *BlobTarget) {
	for name, target := range map[string]*string{"KYNOTES_BLOB_TARGET": &c.URL, "KYNOTES_BLOB_TARGET_ACCESS_KEY": &c.AccessKey, "KYNOTES_BLOB_TARGET_SECRET": &c.Secret, "KYNOTES_BLOB_TARGET_HOST_KEY": &c.HostKey, "KYNOTES_BLOB_TARGET_S3_ENDPOINT": &c.S3Endpoint, "KYNOTES_BLOB_TARGET_S3_REGION": &c.S3Region} {
		if value := os.Getenv(name); value != "" {
			*target = value
		}
	}
}
