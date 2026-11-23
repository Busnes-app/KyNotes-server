package blobstore

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// OrgPrefix, BlobKey and UploadPartKey narrow object-key components at the storage boundary.
// They do not select a backend or introduce a shared-volume implementation.
func OrgPrefix(org string) (string, error) {
	if len(org) == 0 || len(org) > 128 {
		return "", os.ErrInvalid
	}
	for _, c := range org {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", os.ErrInvalid
		}
	}
	return "orgs/" + org + "/", nil
}
func BlobKey(org, digest string) (string, error) {
	prefix, err := OrgPrefix(org)
	if err != nil {
		return "", err
	}
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		return "", os.ErrInvalid
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", os.ErrInvalid
	}
	return prefix + "blobs/" + digest[:2] + "/" + digest[2:4] + "/" + digest, nil
}
func UploadPartKey(org, id string, index int64) (string, error) {
	prefix, err := OrgPrefix(org)
	if err != nil {
		return "", err
	}
	if ids.Validate("ups", id) != nil || index < 0 {
		return "", os.ErrInvalid
	}
	return prefix + "uploads/" + id + "/" + strconv.FormatInt(index, 10), nil
}
