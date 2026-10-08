#!/usr/bin/env bash
# Throwaway KyNotes server for the browser checks: a fresh data directory per run.
# It serves the embedded bundle, so build and sync internal/web/dist first.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
data=$(mktemp -d)
trap 'rm -rf "$data"' EXIT
cat > "$data/kynotes.yaml" <<YAML
server:
  bind: "127.0.0.1:18080"
  dev_insecure_cookies: true
secrets:
  pairing_secret: "12345678901234567890123456789012"
  server_salt_key: "12345678901234567890123456789012"
data_dir: "$data"
YAML
(cd "$root" && go build -o "$data/kynotes-server" ./cmd/kynotes-server)
"$data/kynotes-server" --config "$data/kynotes.yaml"
