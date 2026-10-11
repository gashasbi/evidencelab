#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" && -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
if [[ -z "$PYTHON" ]]; then PYTHON="$(command -v python3)"; fi
PROFILE="${1:-profiles/research-publication-c-cpp-joern.json}"
"$PYTHON" -m evidencelab research-check --root examples/cwe-121 --profile "$PROFILE" --enforce-gates --summary
