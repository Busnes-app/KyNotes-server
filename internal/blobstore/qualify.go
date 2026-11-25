package blobstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	shareds3 "github.com/Busnes-app/ky-primitives/s3"
)

// MaxProviderSkew bounds the provider clock against ours. The orphan sweep ages objects by
// provider LastModified (an hour); a larger skew would let it delete a fresh upload.
const MaxProviderSkew = 5 * time.Minute

// Qualification is what QualifyProvider proved about a bucket. Versioned is informational:
// either way Delete and Purge must leave no version or delete marker behind.
type Qualification struct {
	Versioned bool
	Skew      time.Duration
}

// QualifyProvider checks, under a fresh qualify/<random>/ prefix it removes again, the
// provider behavior multi mode relies on: signatures are verified, If-None-Match: * never
// replaces an object, LastModified is present and within MaxProviderSkew, and a prefix delete
// leaves no version or marker. It needs only the bucket's own read, write, list and delete.
// It does not prove SigV4 request-age refusal or the late-PUT bound (spec, provider
// qualification); those need a signer clock the shared client does not expose.
func QualifyProvider(ctx context.Context, cfg shareds3.Config, now func() time.Time) (Qualification, error) {
	var q Qualification
	c, err := shareds3.New(cfg)
	if err != nil {
		return q, errors.New("qualify: invalid object-store configuration")
	}
	prefix := "qualify/" + strings.ToLower(rand.Text()) + "/"
	key := prefix + "exclusive"
	fail := func(step string, err error) (Qualification, error) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		return q, errors.Join(fmt.Errorf("qualify: %s: %w", step, err), c.DeletePrefix(cleanup, prefix))
	}

	bad := cfg
	bad.SecretKey += "-wrong"
	if wrong, err := shareds3.New(bad); err == nil {
		if _, err := wrong.Head(ctx, key, ""); err == nil || errors.Is(err, shareds3.ErrNotFound) {
			return fail("signatures", errors.New("a request signed with a wrong secret was answered"))
		}
	}
	if _, err := c.PutIfAbsent(ctx, key, strings.NewReader("first"), 5); err != nil {
		return fail("exclusive create", err)
	}
	if _, err := c.PutIfAbsent(ctx, key, strings.NewReader("other"), 5); !errors.Is(err, shareds3.ErrAlreadyExists) {
		return fail("exclusive create", fmt.Errorf("a second If-None-Match: * PUT was not refused (%v)", err))
	}
	body, obj, err := c.Get(ctx, key, "")
	if err != nil {
		return fail("exclusive create", err)
	}
	got, err := io.ReadAll(io.LimitReader(body, 16))
	body.Close()
	if err != nil || string(got) != "first" {
		return fail("exclusive create", errors.New("the refused PUT replaced the object"))
	}
	if obj.LastModified.IsZero() {
		return fail("age metadata", errors.New("no LastModified"))
	}
	q.Skew = now().Sub(obj.LastModified)
	if q.Skew > MaxProviderSkew || q.Skew < -MaxProviderSkew {
		return fail("age metadata", fmt.Errorf("provider clock differs by %s", q.Skew.Round(time.Second)))
	}
	if _, err := c.Put(ctx, key, strings.NewReader("second"), 6); err != nil {
		return fail("versions", err)
	}
	if _, err := c.Delete(ctx, key, ""); err != nil {
		return fail("versions", err)
	}
	page, err := c.ListObjectVersions(ctx, prefix, shareds3.VersionCursor{})
	if err != nil {
		return fail("versions", err)
	}
	q.Versioned = len(page.Objects) > 0
	if err := c.DeletePrefix(ctx, prefix); err != nil {
		return fail("erasure", err)
	}
	if page, err = c.ListObjectVersions(ctx, prefix, shareds3.VersionCursor{}); err != nil {
		return fail("erasure", err)
	}
	if len(page.Objects) > 0 {
		return fail("erasure", fmt.Errorf("%d versions or markers survived the prefix delete", len(page.Objects)))
	}
	return q, nil
}
