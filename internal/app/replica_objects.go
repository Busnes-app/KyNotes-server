package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"

	"github.com/Busnes-app/kynotes-server/internal/blobstore"
)

// newReplicaObjectClient prepares the selected primary-object client without network I/O.
// It is separate from maintenance/fingerprint input: credentials are per replica and never
// belong in shared settings. The gated replica startup binds the control-file protocol.
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

// QualifyObjectStore runs blobstore.QualifyProvider against the configured primary object
// store, with the replica's own bounded credential reader, and reports what it proved.
func QualifyObjectStore(ctx context.Context, out io.Writer) error {
	var in replicaInputs
	for name, dst := range map[string]*string{"KYNOTES_BLOB_S3_ENDPOINT": &in.BlobEndpoint, "KYNOTES_BLOB_S3_BUCKET": &in.BlobBucket, "KYNOTES_BLOB_S3_REGION": &in.BlobRegion} {
		if *dst = os.Getenv(name); *dst == "" {
			return fmt.Errorf("qualify: %s is required", name)
		}
	}
	access, err := replicaObjectCredential("KYNOTES_BLOB_S3_ACCESS_KEY")
	if err != nil {
		return err
	}
	secret, err := replicaObjectCredential("KYNOTES_BLOB_S3_SECRET")
	if err != nil {
		return err
	}
	q, err := blobstore.QualifyProvider(ctx, shareds3.Config{Endpoint: in.BlobEndpoint, Bucket: in.BlobBucket, Region: in.BlobRegion, AccessKey: access, SecretKey: secret}, time.Now)
	if err != nil {
		return err
	}
	versions := "off: Delete and Purge remove the only copy"
	if q.Versioned {
		versions = "on: Delete and Purge removed every version and marker"
	}
	_, err = fmt.Fprintf(out, "Object store qualified: signatures checked, exclusive create refused, LastModified present (skew %s), prefix erasure complete; versioning %s. Not proven here: SigV4 request-age refusal and the late-PUT bound.\n", q.Skew.Round(time.Second), versions)
	return err
}
