#!/usr/bin/env bash
# Throwaway KyNotes server for the browser checks: a fresh data directory per run.
# It serves the embedded bundle, so build and sync internal/web/dist first.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
data=$(mktemp -d)
server=
trap 'if [ -n "$server" ]; then kill "$server" 2>/dev/null; wait "$server" 2>/dev/null; fi; rm -rf "$data"' EXIT
trap 'exit 143' TERM INT
cat > "$data/kynotes.yaml" <<YAML
server:
  bind: "127.0.0.1:18080"
  dev_insecure_cookies: true
secrets:
  pairing_secret: "12345678901234567890123456789012"
  server_salt_key: "12345678901234567890123456789012"
data_dir: "$data"
# Every person in the checks signs in from 127.0.0.1, so they share one per-IP login bucket.
ratelimit:
  login_per_minute: 120
YAML
(cd "$root" && go build -o "$data/kynotes-server" ./cmd/kynotes-server)
# Background plus wait, so a SIGTERM to this script reaches the server instead of orphaning it.
"$data/kynotes-server" --config "$data/kynotes.yaml" &
server=$!
wait "$server"
