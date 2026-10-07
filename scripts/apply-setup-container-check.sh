#!/usr/bin/env bash
# apply-setup inside a real container: socket mode, two runs (second all present), an
# inline secret refused without echo, live deposit routed over the socket, and the socket
# removed on stop.
# Usage: scripts/apply-setup-container-check.sh IMAGE   (run from the repository root)
set -euo pipefail
image=${1:?usage: apply-setup-container-check.sh IMAGE}
name=kynotes-applysetup-check
data=$(mktemp -d)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"; }
trap cleanup EXIT
docker rm -f "$name" >/dev/null 2>&1 || true

cp testdata/config-good/kynotes.yaml "$data/"
mkdir "$data/backups"
printf '%s\n' '{"version":1,"backup":{"dir":"/data/backups","keep":7,"depositInterval":"24h"}}' >"$data/bundle.json"
printf '%s\n' '{"version":1,"sso":{"issuerUrl":"https://id.example","clientId":"kynotes","clientSecret":"inline-secret-value","redirectUri":"https://notes.example/api/v1/auth/oidc/callback"}}' >"$data/inline.json"

docker run -d --name "$name" --user "$(id -u):$(id -g)" -e KYNOTES_BACKUP_DIR=/data/backups -e KYNOTES_BACKUP_KEEP=7 \
  -v "$data:/data" "$image" --config /data/kynotes.yaml >/dev/null
ready=0
for _ in $(seq 1 30); do
  if docker exec "$name" /kynotes-server healthcheck --config /data/kynotes.yaml >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
test "$ready" -eq 1 || { docker logs "$name"; echo "server never became healthy"; exit 1; }

test "$(stat -c %a "$data/admin.sock")" = 600 || { echo "admin.sock is not 0600"; exit 1; }

docker exec "$name" /kynotes-server apply-setup --file /data/bundle.json --config /data/kynotes.yaml >"$data/run1.json"
grep -qF '"section":"backup.interval","status":"created"' "$data/run1.json" || { cat "$data/run1.json"; exit 1; }

docker exec "$name" /kynotes-server apply-setup --file /data/bundle.json --config /data/kynotes.yaml >"$data/run2.json"
if grep -oE '"status":"[a-z]+"' "$data/run2.json" | grep -vqxF '"status":"present"'; then
  cat "$data/run2.json"; echo "second run not all present"; exit 1
fi
test "$(grep -oF '"status":"present"' "$data/run2.json" | wc -l)" -eq 3 || { cat "$data/run2.json"; exit 1; }

# No key is pinned, so the live deposit must fail with the service's precondition code. The
# offline path would fail on the data-directory lock instead.
set +e
docker exec "$name" /kynotes-server deposit --config /data/kynotes.yaml >"$data/deposit.out" 2>"$data/deposit.err"
rc=$?
set -e
test "$rc" -eq 1 && grep -qxF recovery_key_required "$data/deposit.err" || { cat "$data/deposit.err"; echo "live deposit: exit $rc"; exit 1; }

set +e
docker exec "$name" /kynotes-server apply-setup --file /data/inline.json --config /data/kynotes.yaml >"$data/inline.out" 2>"$data/inline.err"
rc=$?
set -e
test "$rc" -eq 2 || { echo "inline secret: exit $rc, want 2"; exit 1; }
if grep -qF inline-secret-value "$data/inline.out" "$data/inline.err"; then echo "inline secret echoed"; exit 1; fi

docker stop "$name" >/dev/null
test ! -e "$data/admin.sock" || { echo "admin.sock left after stop"; exit 1; }
echo "apply-setup container check passed"
