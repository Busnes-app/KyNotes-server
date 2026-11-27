#!/usr/bin/env bash
# Use exactly the ky-primitives version and Go runtime selected by this module.
set -euo pipefail
cd "$(dirname "$0")/.."
pq_toolchain=$(awk '$1 == "toolchain" { print $2 }' go.mod)
test -n "$pq_toolchain"
export GOTOOLCHAIN="$pq_toolchain"
mkdir -p web/public/assets/pq
GOOS=js GOARCH=wasm go build -buildvcs=false -trimpath -o web/public/assets/pq/pq.wasm github.com/Busnes-app/ky-primitives/cmd/pqwasm
install -m 0644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/public/assets/pq/wasm_exec.js
# Keep the module lookup explicit: a missing pinned helper is a build error.
# Resolve after go build so a cold module cache has downloaded ky-primitives.
module=$(go list -m -f '{{.Dir}}' github.com/Busnes-app/ky-primitives)
test -n "$module"
test -f "$module/cmd/pqwasm/hybridsig.go"

mkdir -p internal/web/dist/assets/pq
install -m 0644 web/public/assets/pq/pq.wasm web/public/assets/pq/wasm_exec.js internal/web/dist/assets/pq/
