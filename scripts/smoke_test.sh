#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
echo "[smoke] root=$ROOT"
"$PYTHON" -m evidencelab --version
"$PYTHON" -m pytest -q tests/test_engine.py tests/test_parsers.py tests/test_hardening.py
"$PYTHON" -m evidencelab research-check --root examples/cwe-121 --profile profiles/development-c-cpp-joern.json --summary
