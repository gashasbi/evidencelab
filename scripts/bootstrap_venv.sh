#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" ]]; then
  echo "ERROR: python3 is required to create the EvidenceLab virtual environment" >&2
  exit 2
fi
VENV="${VENV:-$ROOT/.venv}"

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"EvidenceLab requires Python >=3.11; found {sys.version.split()[0]}")
PY

if [[ ! -x "$VENV/bin/python" ]]; then
  "$PYTHON" -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -e "$ROOT[dev]"

echo
printf 'EvidenceLab environment ready:\n  %s\n' "$VENV/bin/python"
printf 'Run tests:\n  %s -m pytest -q\n' "$VENV/bin/python"
printf 'Run doctor:\n  %s -m evidencelab doctor\n' "$VENV/bin/python"
