package blobstore

import (
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// cellSlug is KyIdentity's home region slug (Cells, C1).
var cellSlug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidCell reports whether cell is a home region slug, safe as an object-key component.
func ValidCell(cell string) bool { return cellSlug.MatchString(cell) }

// OrgPrefix, BlobKey and UploadPartKey narrow object-key components at the storage boundary.
// They do not select a backend or introduce a shared-volume implementation. An org's keys sit
// under its cell (its home_region, fixed: orgs never move), so cells can share a bucket.
func OrgPrefix(cell, org string) (string, error) {
	if !ValidCell(cell) || len(org) == 0 || len(org) > 128 {
		return "", os.ErrInvalid
	}
	for _, c := range org {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", os.ErrInvalid
		}
	}
	return "cells/" + cell + "/orgs/" + org + "/", nil
}
func BlobKey(cell, org, digest string) (string, error) {
	prefix, err := OrgPrefix(cell, org)
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
func UploadPartKey(cell, org, id string, index int64) (string, error) {
	prefix, err := OrgPrefix(cell, org)
	if err != nil {
		return "", err
	}
	if ids.Validate("ups", id) != nil || index < 0 {
		return "", os.ErrInvalid
	}
	return prefix + "uploads/" + id + "/" + strconv.FormatInt(index, 10), nil
}
