package blobstore

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestBackendSeamPreservesVolumeAndRefusesOrgPurge(t *testing.T) {
	volume, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var b Backend = volume
	tmp, err := b.NewTemp("seam-save")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tmp, "opaque ciphertext"); err != nil {
		t.Fatal(err)
	}
	digest, size, err := tmp.Finalize("")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DeletePrefix("cells/eu/orgs/org_customer/"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("volume accepted multi-org purge: %v", err)
	}
	reader, n, err := b.Open(digest)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil || n != size || string(raw) != "opaque ciphertext" {
		t.Fatalf("volume stream changed: %q %d %v", raw, n, err)
	}
}

func TestObjectKeysSeparateOrgsAndRefusePathComponents(t *testing.T) {
	digest := strings.Repeat("a", 64)
	id := "ups_" + strings.Repeat("a", 26)
	a, err := BlobKey("eu", "org_a", digest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BlobKey("eu", "org_b", digest)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := BlobKey("us-east-2", "org_a", digest); err != nil || c == a {
		t.Fatalf("cell key collision: %q %q %v", a, c, err)
	}
	for _, cell := range []string{"", "e", "EU", "../eu", "eu/x", "eu%2f", strings.Repeat("a", 33)} {
		if _, err := BlobKey(cell, "org_a", digest); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("unsafe cell %q accepted: %v", cell, err)
		}
	}
	if a == b || a != "cells/eu/orgs/org_a/blobs/aa/aa/"+digest {
		t.Fatalf("org key collision: %q %q", a, b)
	}
	part, err := UploadPartKey("eu", "org_a", id, 1)
	if err != nil || part != "cells/eu/orgs/org_a/uploads/"+id+"/1" {
		t.Fatalf("part key %q %v", part, err)
	}
	for _, org := range []string{"", ".", "..", "org/a", "org\\a", "org%2fa", "org\x00a", strings.Repeat("a", 129)} {
		if _, err := BlobKey("eu", org, digest); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("unsafe org %q accepted: %v", org, err)
		}
	}
	for _, bad := range []string{"../" + digest, digest[:63], strings.Repeat("g", 64), strings.Repeat("A", 64)} {
		if _, err := BlobKey("eu", "org_a", bad); err == nil {
			t.Errorf("bad digest %q accepted", bad)
		}
	}
	for _, bad := range []string{"../" + id, "ups_bad", id + "/0"} {
		if _, err := UploadPartKey("eu", "org_a", bad, 0); err == nil {
			t.Errorf("bad upload ID accepted: %q", bad)
		}
	}
	if _, err := UploadPartKey("eu", "org_a", id, -1); err == nil {
		t.Fatal("negative part index accepted")
	}
}
