#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for cmd in joern-parse joern-export joern-slice; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd not found in PATH" >&2; exit 2; }
done

PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python"
  else
    PYTHON="$(command -v python3)"
  fi
fi

"$PYTHON" - <<'PY'
import sys
import evidencelab
print(f"[E2E] Python: {sys.executable}")
print(f"[E2E] EvidenceLab: {evidencelab.__version__}")
PY

OUT="${1:-/tmp/evidencelab-joern-e2e}"
CASE_TIMEOUT="${EVIDENCELAB_E2E_CASE_TIMEOUT:-600}"

if ! [[ "$CASE_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$CASE_TIMEOUT" -lt 1 ]]; then
  echo "ERROR: EVIDENCELAB_E2E_CASE_TIMEOUT must be a positive integer" >&2
  exit 2
fi

rm -rf "$OUT"
mkdir -p "$OUT"

echo "[E2E] Root: $ROOT"
echo "[E2E] Output: $OUT"
echo "[E2E] Per-case timeout: ${CASE_TIMEOUT}s"

echo "[E2E] No global timeout is imposed; each Joern case is bounded independently."

PYTHONUNBUFFERED=1 "$PYTHON" - "$OUT" "$CASE_TIMEOUT" <<'PY'
import json
import os
import signal
import subprocess
import sys
import traceback
from pathlib import Path

root = Path('.').resolve()
out = Path(sys.argv[1]).resolve()
case_timeout = int(sys.argv[2])
sources = sorted((root / 'examples/cwe-121/corpus/source').glob('*.c'))

if not sources:
    print('[E2E] ERROR: no C source cases found', file=sys.stderr, flush=True)
    raise SystemExit(2)

report = []
print(f'[E2E] Cases: {len(sources)}', flush=True)

def run_bounded(cmd, *, timeout, **kwargs):
    proc = subprocess.Popen(cmd, start_new_session=True, **kwargs)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise

for index, src in enumerate(sources, start=1):
    stem = src.stem
    dest = out / stem
    dest.mkdir(parents=True, exist_ok=True)
    log_path = dest / 'e2e.log'

    print(f'[{index}/{len(sources)}] {stem}: CAPTURE', flush=True)
    capture_cmd = [
        sys.executable, '-m', 'evidencelab', 'capture',
        '--source', str(src.resolve()), '--out', str(dest),
        '--dataflow-slice-depth', os.environ.get('EVIDENCELAB_E2E_SLICE_DEPTH', '8'),
        '--dataflow-timeout', os.environ.get('EVIDENCELAB_E2E_DATAFLOW_TIMEOUT', '240'),
        '--dataflow-file-filter', src.name,
        '--best-effort-dataflow',
    ]
    try:
        with log_path.open('w', encoding='utf-8') as log:
            proc = subprocess.Popen(
                capture_cmd,
                text=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=case_timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                raise
            class Completed:
                returncode = rc
            cap = Completed()
    except subprocess.TimeoutExpired:
        print(f'[{index}/{len(sources)}] {stem}: TIMEOUT after {case_timeout}s', file=sys.stderr, flush=True)
        report.append({"source": str(src), "status": "TIMEOUT", "log": str(log_path)})
        continue
    except Exception as exc:
        print(f'[{index}/{len(sources)}] {stem}: CAPTURE ERROR: {exc}', file=sys.stderr, flush=True)
        traceback.print_exc()
        report.append({"source": str(src), "status": "ERROR", "log": str(log_path)})
        continue

    if cap.returncode != 0:
        tail = log_path.read_text(encoding='utf-8', errors='replace').splitlines()[-20:]
        print(f'[{index}/{len(sources)}] {stem}: CAPTURE FAILED (exit {cap.returncode})', file=sys.stderr, flush=True)
        if tail:
            print('\n'.join(tail), file=sys.stderr, flush=True)
        report.append({"source": str(src), "status": "CAPTURE_FAILED", "returncode": cap.returncode, "log": str(log_path)})
        continue

    graphml = dest / 'graphml' / 'export.xml'
    dataflow = dest / 'dataflow.json'
    merged = dest / 'merged.json'
    if not graphml.is_file():
        print(f'[{index}/{len(sources)}] {stem}: missing GraphML artifact', file=sys.stderr, flush=True)
        report.append({"source": str(src), "status": "MISSING_GRAPHML", "log": str(log_path)})
        continue

    print(f'[{index}/{len(sources)}] {stem}: MERGE', flush=True)
    cmd = [sys.executable, '-m', 'evidencelab', 'merge', '--graph', str(graphml)]
    if dataflow.is_file():
        cmd += ['--graph', str(dataflow)]
    cmd += ['--out', str(merged), '--pretty']
    manifest_path = dest / 'capture-manifest.json'
    if manifest_path.is_file():
        try:
            capture_status = json.loads(
                manifest_path.read_text(encoding='utf-8')
            ).get('status')
        except Exception:
            capture_status = None
        if capture_status != 'DEGRADED':
            cmd += ['--manifest', str(manifest_path)]
    try:
        proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=case_timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
            raise
        class MergeResult:
            returncode = proc.returncode
            stdout = stdout or ""
            stderr = stderr or ""
        proc = MergeResult()
    except subprocess.TimeoutExpired:
        print(f'[{index}/{len(sources)}] {stem}: MERGE TIMEOUT after {case_timeout}s', file=sys.stderr, flush=True)
        report.append({"source": str(src), "status": "MERGE_TIMEOUT", "log": str(log_path)})
        continue
    if proc.returncode != 0:
        print(f'[{index}/{len(sources)}] {stem}: MERGE FAILED (exit {proc.returncode})', file=sys.stderr, flush=True)
        if proc.stdout:
            print(proc.stdout[-4000:], file=sys.stderr, flush=True)
        if proc.stderr:
            print(proc.stderr[-4000:], file=sys.stderr, flush=True)
        report.append({"source": str(src), "status": "MERGE_FAILED", "returncode": proc.returncode, "log": str(log_path)})
        continue

    manifest_path = dest / 'capture-manifest.json'
    dataflow_status = 'UNKNOWN'
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            dataflow_status = manifest.get('analysis', {}).get('dataflow', {}).get('status', 'UNKNOWN')
        except Exception:
            dataflow_status = 'MANIFEST_UNREADABLE'
    case_status = 'PASS' if dataflow_status in {'OK', 'NOT_REQUESTED'} else 'PASS_WITH_WARNING'
    print(f'[{index}/{len(sources)}] {stem}: {case_status} (dataflow={dataflow_status})', flush=True)
    report.append({
        "source": str(src),
        "capture": str(dest / 'capture-manifest.json'),
        "merged": str(merged),
        "log": str(log_path),
        "status": case_status,
        "dataflow_status": dataflow_status,
    })

failed = [x for x in report if x['status'] not in {'PASS', 'PASS_WITH_WARNING'}]
warnings = [x for x in report if x['status'] == 'PASS_WITH_WARNING']
status = 'FAIL' if failed or len(report) != len(sources) else ('PASS_WITH_WARNINGS' if warnings else 'PASS')
payload = {
    "status": status,
    "cases": report,
    "case_count": len(sources),
    "failed_count": len(failed),
    "case_timeout_seconds": case_timeout,
}
(out / 'e2e-report.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
print(json.dumps(payload, indent=2), flush=True)
strict = os.environ.get('EVIDENCELAB_E2E_STRICT', '0') == '1'
raise SystemExit(0 if status == 'PASS' or (status == 'PASS_WITH_WARNINGS' and not strict) else 1)
PY
