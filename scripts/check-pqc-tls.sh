#!/usr/bin/env bash
# Refuse classical TLS overrides and prove outbound PQ hybrid key exchange (X25519MLKEM768).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

mapfile -d '' go_files < <(git ls-files -z --cached --others --exclude-standard -- '*.go' ':!*_test.go')
bad=""
if [ "${#go_files[@]}" -gt 0 ]; then
  bad=$(grep -nHE '\bCurvePreferences\b' -- "${go_files[@]}" || true)
fi
if [ -n "$bad" ]; then
  echo "CurvePreferences is forbidden in non-test Go code (keep Go's hybrid PQ TLS defaults):" >&2
  echo "$bad" >&2
  exit 1
fi

mapfile -d '' tlsmlkem_files < <(git ls-files -z --cached --others --exclude-standard -- \
  '*.go' '*.sh' '*.py' 'go.mod' '*/go.mod' 'Makefile' \
  '.github/workflows/*' '*Dockerfile*' '*dockerfile*' '*compose*.yml' '*compose*.yaml' \
  ':!*_test.go' ':!scripts/check-pqc-tls.sh')
bad=""
if [ "${#tlsmlkem_files[@]}" -gt 0 ]; then
  bad=$(grep -nHiE 'tlsmlkem' -- "${tlsmlkem_files[@]}" || true)
fi
if [ -n "$bad" ]; then
  echo "tlsmlkem overrides are forbidden in non-test code, workflows, Dockerfiles, and Compose files:" >&2
  echo "$bad" >&2
  exit 1
fi

go test -race -count=1 -run '^TestOutboundTLSPQHandshake$' ./internal/sso
GODEBUG=fips140=on go test -race -count=1 -run '^TestOutboundTLSPQHandshake$' ./internal/sso
