package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
)

// newReplicaObjectClient prepares the selected primary-object client without network I/O.
// It is separate from maintenance/fingerprint input: credentials are per replica and never
// belong in shared settings. Startup remains refused until every hosted prerequisite exists.
func newReplicaObjectClient(in replicaInputs) (*shareds3.Client, error) {
	access, err := replicaObjectCredential("KYNOTES_BLOB_S3_ACCESS_KEY")
	if err != nil {
		return nil, err
	}
	secret, err := replicaObjectCredential("KYNOTES_BLOB_S3_SECRET")
	if err != nil {
		return nil, err
	}
	client, err := shareds3.New(shareds3.Config{
		Endpoint: in.BlobEndpoint, Bucket: in.BlobBucket, Region: in.BlobRegion,
		AccessKey: access, SecretKey: secret,
	})
	if err != nil {
		return nil, errors.New("replicas: invalid primary object-store configuration")
	}
	return client, nil
}

// These paths are operator configuration. Refuse nonregular files before opening them (in
// particular FIFOs/devices); keep the read bounded even if a regular file grows while read.
// Errors name only the setting, never its value, path or an underlying filesystem error.
func replicaObjectCredential(name string) (string, error) {
	const maxBytes = 64 << 10
	value, direct := os.LookupEnv(name)
	path, file := os.LookupEnv(name + "_FILE")
	if direct && file {
		return "", fmt.Errorf("replicas: set only one of %s and %s_FILE", name, name)
	}
	if file {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("replicas: %s_FILE must name a readable regular file", name)
		}
		f, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("replicas: %s_FILE cannot be read", name)
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, maxBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(raw) > maxBytes {
			return "", fmt.Errorf("replicas: %s_FILE cannot be read within the credential limit", name)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	if value == "" || len(value) > maxBytes || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("replicas: %s requires one nonempty credential of at most 64 KiB", name)
	}
	return value, nil
}
