#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" && -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
if [[ -z "$PYTHON" ]]; then PYTHON="$(command -v python3)"; fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
"$PYTHON" - <<'PY'
import evidencelab
assert evidencelab.__version__ == '1.0.0'
assert evidencelab.SCHEMA_VERSION == '1.0'
assert evidencelab.SUPPORTED_SCHEMA_VERSIONS == frozenset({'1.0'})
print('EvidenceLab 1.0.0 release/schema verification: PASS')
PY
"$PYTHON" -m compileall -q evidencelab
"$PYTHON" -m evidencelab evidence validate --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els >/tmp/evidencelab-release-evidence-validate.json
"$PYTHON" -m evidencelab dataset-model-validate --model examples/dataset-model/simple-vuln-dataset.json >/tmp/evidencelab-release-dataset-validate.json
"$PYTHON" - <<'PY'
import json
for p in ('/tmp/evidencelab-release-evidence-validate.json','/tmp/evidencelab-release-dataset-validate.json'):
    d=json.load(open(p)); assert d['status']=='PASS', d
print('release DSL + dataset-model validation: PASS')
PY
