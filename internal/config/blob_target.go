package config

import (
	"crypto/fips140"
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
	if err := blobTransportPolicy(u, c); err != nil {
		return err
	}
	if strings.EqualFold(u.Scheme, "sftp") && c.HostKey == "" {
		return errors.New("backup.blob_target: SFTP requires a verified SHA256 host key fingerprint")
	}
	if _, err := offsite.Parse(c.Offsite()); err != nil {
		return errors.New("backup.blob_target: invalid target or missing credentials; use file, S3, pinned SFTP or SMB with separate credential fields")
	}
	return nil
}

// blobTransportPolicy keeps every transfer on SSH or TLS under the strong-crypto profile
// (docs/STRONG-CRYPTO.md). Normal and probe loading both apply it.
func blobTransportPolicy(u *url.URL, c BlobTarget) error {
	if !fips140.Enabled() {
		return nil
	}
	if strings.EqualFold(u.Scheme, "smb") {
		return errors.New("backup.blob_target.url: SMB uses NTLM (MD4, HMAC-MD5, RC4), refused under GODEBUG=fips140=on; use pinned SFTP, HTTPS S3 or file")
	}
	if e, err := url.Parse(c.S3Endpoint); c.S3Endpoint != "" && (err != nil || !strings.EqualFold(e.Scheme, "https")) {
		return errors.New("backup.blob_target.s3_endpoint: must be HTTPS under GODEBUG=fips140=on")
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
