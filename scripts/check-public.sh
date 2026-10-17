#!/usr/bin/env bash
# Fails if anything private has found its way into this public repository.
#
# The agent is open source, so this repo may depend on nothing private and must
# not name anything internal: no private module paths, no internal hostnames.
# CI runs this on every change. Run it locally before pushing:
#
#     scripts/check-public.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Private repositories and hosts. Add a name here when a new private repo exists.
patterns=(
  'gitlab\.atomity\.de'
  'atomity-contract-go'
  'atomity-contracts'
  'atomity-agent-iam'
  'atomity-k8s-connector'
  'atomity-gateway'
  'atomity-iam'
  'atomity-tenant'
)
regex="$(IFS='|'; echo "${patterns[*]}")"

# Everything tracked or not yet ignored, except this script (which names them)
# and the version-control directory.
if hits="$(grep -rInE "$regex" . \
    --exclude-dir=.git \
    --exclude=check-public.sh \
    --exclude=go.sum)"; then
  echo "ERROR: private names found in the public repository:" >&2
  echo "$hits" >&2
  exit 1
fi

# No module in this repository may require a private module either. This is
# redundant with the check above for named repos, and catches a replace
# directive that points at a local path outside the repository.
if bad="$(grep -rIn --include=go.mod -E '^\s*replace\s' . )"; then
  echo "ERROR: replace directives are not allowed in a public module:" >&2
  echo "$bad" >&2
  exit 1
fi

echo "ok: nothing private found"
