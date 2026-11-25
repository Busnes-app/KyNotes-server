package app

import (
	"io"
	"strings"
	"testing"
)

// qualify-object-store needs the full object-store environment, one credential form per key,
// and an HTTPS endpoint; it never echoes a credential.
func TestQualifyObjectStoreRefusesIncompleteInput(t *testing.T) {
	base := map[string]string{"KYNOTES_BLOB_S3_ENDPOINT": "https://s3.invalid", "KYNOTES_BLOB_S3_BUCKET": "b", "KYNOTES_BLOB_S3_REGION": "r", "KYNOTES_BLOB_S3_ACCESS_KEY": "AKIDSECRETVALUE", "KYNOTES_BLOB_S3_SECRET": "very-secret-value"}
	for _, c := range []struct{ drop, set, value, want string }{
		{drop: "KYNOTES_BLOB_S3_ENDPOINT", want: "KYNOTES_BLOB_S3_ENDPOINT is required"},
		{drop: "KYNOTES_BLOB_S3_SECRET", want: "KYNOTES_BLOB_S3_SECRET requires"},
		{set: "KYNOTES_BLOB_S3_SECRET_FILE", value: "/nonexistent", want: "set only one"},
		{set: "KYNOTES_BLOB_S3_ENDPOINT", value: "http://s3.invalid", want: "invalid object-store configuration"},
	} {
		t.Run(c.want, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			if c.drop != "" {
				t.Setenv(c.drop, "")
			}
			if c.set != "" {
				t.Setenv(c.set, c.value)
			}
			err := QualifyObjectStore(t.Context(), io.Discard)
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "very-secret") || strings.Contains(err.Error(), "AKIDSECRET") {
				t.Errorf("%+v: %v", c, err)
			}
		})
	}
}
