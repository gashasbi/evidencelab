#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then PYTHON="$VIRTUAL_ENV/bin/python"; else PYTHON="$(command -v python3)"; fi
fi
command -v joern-parse >/dev/null || { echo "ERROR: joern-parse not found" >&2; exit 2; }
command -v joern-export >/dev/null || { echo "ERROR: joern-export not found" >&2; exit 2; }
command -v joern-slice >/dev/null || { echo "ERROR: joern-slice not found" >&2; exit 2; }
exec "$PYTHON" "$ROOT/scripts/cwe120_research_e2e.py" "$@"
