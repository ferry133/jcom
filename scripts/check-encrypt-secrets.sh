#!/usr/bin/env bash
# Regression test for scripts/encrypt-secrets.sh.
#
# The first version of that script passed a hand-written test suite and still
# churned on every real run. The fixtures were written by hand and encrypted
# with sops, so BOTH sides of its comparison had been through sops — and the
# renderer, which emits a leading `---` document marker that sops does not
# return, was never in the loop. The test was right; the inputs were not.
#
# So every fixture here is renderer-shaped: leading `---`, comments, quoted
# scalars, two-space indent. That is what makejinja actually writes.
set -euo pipefail

S="$(cd "$(dirname "$0")" && pwd)/encrypt-secrets.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cd "$T"

git init -q .
age-keygen -o age.key 2>/dev/null
printf 'creation_rules:\n  - path_regex: .*\n    age: "%s"\n' "$(age-keygen -y age.key)" > .sops.yaml
export SOPS_AGE_KEY_FILE="$T/age.key"
mkdir -p kubernetes

render() {  # renderer-shaped output, exactly as makejinja writes it
cat > kubernetes/cluster-secrets.sops.yaml <<'EOF'
---
apiVersion: v1
kind: Secret
metadata:
  name: cluster-secrets
stringData:
  # a comment the renderer emits
  CLOUDFLARE_TOKEN: "TOKEN_PLACEHOLDER"
  TTYD_CREDENTIAL: ""
EOF
  [ -n "${1:-}" ] && sed -i.bak "s/TOKEN_PLACEHOLDER/$1/" kubernetes/cluster-secrets.sops.yaml && rm -f kubernetes/cluster-secrets.sops.yaml.bak
  return 0
}

fail=0
check() { # name expected_status
  if [ "$(git status --porcelain kubernetes | wc -l | tr -d ' ')" = "$2" ]; then
    echo "PASS  $1"
  else
    echo "FAIL  $1 — git reported $(git status --porcelain kubernetes | wc -l | tr -d ' ') changed file(s), expected $2"
    fail=$((fail+1))
  fi
}

render original-value
sops --encrypt --in-place kubernetes/cluster-secrets.sops.yaml
git add -A && git -c user.email=t@t -c user.name=t commit -qm baseline

# 1. Re-render with identical content: must produce no diff at all.
render original-value
bash "$S" kubernetes >/dev/null
check "no-op render leaves git clean (the leading --- case)" 0

# 2. Twice in a row.
render original-value; bash "$S" kubernetes >/dev/null
render original-value; bash "$S" kubernetes >/dev/null
check "two consecutive renders stay clean" 0

# 3. A real change must still come through.
render rotated-value
bash "$S" kubernetes >/dev/null
check "a changed secret is re-encrypted and visible" 1
if sops -d kubernetes/cluster-secrets.sops.yaml | grep -q rotated-value; then
  echo "PASS  the new value is what got encrypted"
else
  echo "FAIL  the new value was lost"; fail=$((fail+1))
fi

echo
[ "$fail" = 0 ] && { echo "ok — encrypt-secrets.sh is idempotent on renderer-shaped input"; exit 0; }
echo "$fail check(s) failed."
exit 1
