#!/usr/bin/env bash
#
# Checks that the Barry installed by scripts/install-barry.sh works: runs
# Barry's minimal example (a descriptor with only "ta.cer") in a temporary
# directory and checks that it writes a TAL and an rsync tree.
#
#   LUMINA_TOOLS  install prefix (default: <repo>/_tools)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BARRY="${LUMINA_TOOLS:-$ROOT/_tools}/bin/barry"

if [[ ! -x "$BARRY" ]]; then
  echo "Barry not found at $BARRY. Run scripts/install-barry.sh first." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "ta.cer" > minimal.repo
"$BARRY" minimal.repo > /dev/null

status=0
for f in minimal.tal rsync/ta.cer rsync/ta/ta.crl rsync/ta/ta.mft; do
  if [[ -s "$f" ]]; then
    echo "ok       $f"
  else
    echo "MISSING  $f" >&2
    status=1
  fi
done

if grep -q '^rsync://' minimal.tal; then
  echo "ok       minimal.tal has an rsync URI"
else
  echo "FAIL     minimal.tal has no rsync URI" >&2
  status=1
fi

exit $status
