#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" && -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
if [[ -z "$PYTHON" ]]; then PYTHON="$(command -v python3)"; fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD="${PYTEST_DISABLE_PLUGIN_AUTOLOAD:-1}"

bash scripts/verify_release.sh
"$PYTHON" -m compileall -q evidencelab

run_isolated_tests() {
  local timeout_seconds="${RELEASE_TEST_FILE_TIMEOUT:-180}"
  "$PYTHON" scripts/run_isolated_tests.py --timeout "$timeout_seconds"
}

run_isolated_tests

"$PYTHON" -m evidencelab research-audit --root examples/cwe-121 --out /tmp/evidencelab-release-audit.json >/tmp/evidencelab-release-audit.stdout
"$PYTHON" -m evidencelab research-check --root examples/cwe-121 --profile profiles/development-c-cpp-joern.json --summary >/tmp/evidencelab-release-dev.json
"$PYTHON" - <<'PY'
import json
assert json.load(open('/tmp/evidencelab-release-audit.json'))['status']=='PASS'
assert not json.load(open('/tmp/evidencelab-release-audit.json')).get('warnings')
assert json.load(open('/tmp/evidencelab-release-dev.json'))['status']=='PASS'
print('reference audit + development evaluation: PASS')
PY

"$PYTHON" -m evidencelab evidence compile --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els --out /tmp/evidencelab-release-evidence.json
"$PYTHON" -m evidencelab evidence run --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els --graph examples/cwe-121/graphs/vulnerable.json --out /tmp/evidencelab-release-evidence-result.json >/tmp/evidencelab-release-evidence-result.stdout
"$PYTHON" -m evidencelab dataset-model-preview --model examples/dataset-model/simple-vuln-dataset.json --limit 3 >/tmp/evidencelab-release-dataset-preview.json
"$PYTHON" -m evidencelab dataset-model-import --model examples/dataset-model/simple-vuln-dataset.json --out /tmp/evidencelab-release-dataset.json
"$PYTHON" - <<'PY'
import json
r=json.load(open('/tmp/evidencelab-release-evidence-result.stdout'))
assert r['status']=='MATCH', r
m=json.load(open('/tmp/evidencelab-release-dataset.json'))
assert m['schema_version']=='1.0' and m['case_count']==3
print('Evidence + dataset materialization smoke: PASS')
PY

if [[ "${SKIP_JOERN_E2E:-0}" != "1" ]]; then
  ./scripts/joern_e2e.sh
fi

echo 'EvidenceLab 1.0.0 release test: PASS'
