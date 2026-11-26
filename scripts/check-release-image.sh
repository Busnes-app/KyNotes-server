#!/usr/bin/env bash
# Usage: check-release-image.sh <image>
# Fails unless the image is a release build: its binary carries no end-to-end build tag, and a
# complete multi-tenant configuration still meets the release refusal
# (KyCalendar docs/superpowers/specs/2026-11-24-multi-tenant-e2e-design.md, Mechanism).
set -euo pipefail
image=${1:?usage: check-release-image.sh <image>}
dir=$(mktemp -d)
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$dir"' EXIT
docker cp -q "$cid:/kynotes-server" "$dir/kynotes-server"

info=$(go version -m "$dir/kynotes-server")
grep -q -P '^\tpath\tgithub\.com/Busnes-app/kynotes-server/cmd/kynotes-server$' <<<"$info" ||
  { echo "::error::$image: no build info for kynotes-server:" >&2; echo "$info" >&2; exit 1; }
if tags=$(grep -P '^\tbuild\t-tags=' <<<"$info") && grep -q -w kye2e <<<"$tags"; then
  echo "::error::$image was built with the end-to-end test tag: $tags" >&2
  exit 1
fi

# A complete multi-tenant configuration, issuer under .test as the test build wants: only the
# release gate may refuse it. --network none: nothing it could reach exists anyway.
set +e
out=$(docker run --rm --network none --memory 256m \
  -e KYNOTES_TENANCY=multi \
  -e KYNOTES_STAFF_ORG_ID=org-staff \
  -e KYNOTES_REGION=e2e-1 \
  -e KYNOTES_DB_DSN=postgres://notes:pw@db/notes \
  -e KYNOTES_SSO_ISSUER=https://id.e2e.test \
  -e KYNOTES_SSO_CLIENT_ID=kynotes \
  -e KYNOTES_SSO_CLIENT_SECRET=secret \
  -e KYNOTES_SSO_HMAC_SECRET="$(printf 'h%.0s' {1..32})" \
  -e KYNOTES_SECRETS_PAIRING_SECRET="$(printf 'p%.0s' {1..32})" \
  -e KYNOTES_SECRETS_SERVER_SALT_KEY="$(printf 's%.0s' {1..32})" \
  "$image" 2>&1)
code=$?
set -e
if [ "$code" -eq 0 ] || ! grep -qF 'KYNOTES_TENANCY: multi is not available in this release' <<<"$out"; then
  echo "::error::$image did not refuse a complete multi-tenant configuration at the release gate (exit $code):" >&2
  echo "$out" >&2
  exit 1
fi
echo "$image: release build, multi-tenant startup refused"
