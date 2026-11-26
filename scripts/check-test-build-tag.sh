#!/usr/bin/env bash
# The suite end-to-end build tag opens multi-tenant startup, so it may appear only in the gate
# files, e2e/, docs and these checks, and no release path may pass build tags at all
# (KyCalendar docs/superpowers/specs/2026-11-24-multi-tenant-e2e-design.md, Mechanism).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
tag=kye2e
fail=0

stray=$(git grep -l -i "$tag" -- . \
  ':!internal/config/gate_release.go' ':!internal/config/gate_kye2e.go' \
  ':!internal/config/gate_release_test.go' ':!internal/config/gate_kye2e_test.go' \
  ':!e2e/' ':!*.md' ':!scripts/check-test-build-tag.sh' ':!scripts/check-release-image.sh' || true)
if [ -n "$stray" ]; then
  echo "::error::the $tag build tag appears outside the gate files and e2e/:" >&2
  echo "$stray" >&2
  fail=1
fi

# A -tags (or GOFLAGS) in a release path would let a release build pass the tag without editing
# a gate file. git describe --tags is the only other use of the word there.
mapfile -t release < <(git ls-files -- Makefile 'Dockerfile*' '*/Dockerfile*' 'docker-compose*.yml' \
  .github/workflows/ci.yml .github/workflows/release-image.yml .github/workflows/dependency-release.yml | grep -v '^e2e/')
if found=$(grep -n -H -E -- '(^|[^[:alnum:]_])-{1,2}tags([=[:space:]"]|$)|GOFLAGS' "${release[@]}" | grep -v 'git describe'); then
  echo "::error::a release path passes build tags:" >&2
  echo "$found" >&2
  fail=1
fi

# Both gate files exist and say what they must.
{ grep -qx '//go:build !kye2e' internal/config/gate_release.go && grep -qx 'const multiTenantBuild = false' internal/config/gate_release.go; } ||
  { echo "::error::internal/config/gate_release.go must be //go:build !$tag with multiTenantBuild = false" >&2; fail=1; }
{ grep -qx '//go:build kye2e' internal/config/gate_kye2e.go && grep -qx 'const multiTenantBuild = true' internal/config/gate_kye2e.go; } ||
  { echo "::error::internal/config/gate_kye2e.go must be //go:build $tag with multiTenantBuild = true" >&2; fail=1; }
[ "$fail" -eq 0 ] || exit 1

# The untagged build refuses multi; the tagged test build compiles and opens the gate only under
# a .test issuer.
go vet -tags "$tag" ./internal/config/... ./cmd/...
go test -count=1 ./internal/config/...
go test -count=1 -tags "$tag" ./internal/config/...
