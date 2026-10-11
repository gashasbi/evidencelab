#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="$(PYTHONPATH="$ROOT" python3 -c 'import evidencelab; print(evidencelab.__version__)')"
OUT_DIR="${1:-$ROOT/dist}"
if [[ "$OUT_DIR" != /* ]]; then OUT_DIR="$ROOT/$OUT_DIR"; fi
ARCHIVE="${2:-evidencelab-${VERSION}.zip}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp -a . "$TMP/project"
cd "$TMP/project"
rm -rf .git .venv venv .pytest_cache dist build __pycache__
find . -type d -name '__pycache__' -prune -exec rm -rf {} +
find . -type d -name '.pytest_cache' -prune -exec rm -rf {} +
find . -type f -name '*.pyc' -delete
zip -q -r "$OUT_DIR/$ARCHIVE" . -x '*.DS_Store'
cd "$ROOT"
unzip -t "$OUT_DIR/$ARCHIVE" >/dev/null
FIRST_TOP="$(unzip -Z1 "$OUT_DIR/$ARCHIVE" | awk -F/ 'NF{print $1; exit}')"
if [[ "$FIRST_TOP" == "el123" || "$FIRST_TOP" == "evidencelab-pro" ]]; then
  echo "ERROR: release archive has an unexpected wrapper directory: $FIRST_TOP" >&2
  exit 1
fi
if unzip -Z1 "$OUT_DIR/$ARCHIVE" | grep -Eq '(^|/)(\.pytest_cache|\.?venv)(/|$)|(^|/)__pycache__|\.pyc$|(^|/)(dist|build)/'; then
  echo "ERROR: release archive contains build/test cache files" >&2
  exit 1
fi
printf '%s\n' "$OUT_DIR/$ARCHIVE"
