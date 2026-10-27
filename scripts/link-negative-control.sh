#!/usr/bin/env bash
# Negative control for the device-link bundle (web/src/linking.ts): the linking tests must pass as
# committed and fail when the HPKE info binding or Auth-mode sender authentication is removed.
# Mutates linking.ts in place and restores it from git, so it refuses to run on uncommitted edits.
set -euo pipefail
cd "$(dirname "$0")/../web"
target=src/linking.ts
if ! git diff --quiet HEAD -- "$target"; then
  echo "refusing: $target has uncommitted changes (a killed run? git checkout -- web/$target)" >&2
  exit 2
fi
run() { npx vitest run src/linking.test.ts >"$1" 2>&1; }

# mutate NAME FROM TO...: replaces each exact FROM with TO; each must occur exactly once.
mutate() {
  node -e '
    const fs = require("fs");
    const [file, ...pairs] = process.argv.slice(1);
    let text = fs.readFileSync(file, "utf8");
    for (let i = 0; i < pairs.length; i += 2) {
      if (text.split(pairs[i]).length !== 2) { console.error("mutation did not apply: " + pairs[i]); process.exit(3); }
      text = text.replace(pairs[i], pairs[i + 1]);
    }
    fs.writeFileSync(file, text);
  ' "$target" "$@"
}

log=$(mktemp)
trap 'git checkout -- "$target"; rm -f "$log"' EXIT

run "$log" || { cat "$log"; echo "baseline: linking tests fail unmutated" >&2; exit 1; }
echo "baseline: pass"

status=0
control() {
  local name=$1; shift
  git checkout -- "$target"
  mutate "$@"
  if run "$log"; then
    echo "$name: tests still PASS (control failed)"; status=1
  else
    echo "$name: tests fail as expected:"; grep -E '^ +× |AssertionError' "$log" | sed 's/^/  /' | sort -u
  fi
}

control "info without binding" \
  'const linkInfo = (c: LinkContext) => concat(' 'const linkInfo = (c: LinkContext) => encoder.encode(LINK_LABEL) ?? concat('
control "mode_base (no sender authentication)" \
  'senderKey: await hpkeKeyPair(approver.privateKey), ' '' \
  'senderPublicKey: await envelopeSuite.kem.deserializePublicKey(context.approverKey),' ''
exit "$status"
