#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
echo "[research-smoke] root=$ROOT"
"$PYTHON" -m evidencelab --version
"$PYTHON" -m pytest -q tests/test_engine.py tests/test_hardening.py tests/test_release_integrity.py
"$PYTHON" -m evidencelab research-audit --root examples/cwe-121
"$PYTHON" -m evidencelab research-check --root examples/cwe-121 --profile profiles/development-c-cpp-joern.json --summary
