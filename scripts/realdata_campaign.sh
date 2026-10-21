#!/usr/bin/env bash
# End-to-end real-data campaign using EvidenceLab's existing import/capture/evaluate APIs.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CWE="CWE-120"
PRIMEVUL=""
SECVULEVAL=""
DATA_ROOT="${EVIDENCELAB_DATA_ROOT:-$HOME/evidencelab-research-data}"
OUT_ROOT=""
PROFILE="$ROOT/profiles/research-publication-c-cpp-joern.json"
LIMIT=""
TIMEOUT="600"
PREPARE_ONLY=0
FETCH_PILOT=0
HIDDEN_ROOT="${EVIDENCELAB_HIDDEN_ROOT:-}"
HIDDEN_KEY_ENV="${EVIDENCELAB_HIDDEN_KEY_ENV:-}"

usage() {
  cat <<'EOF'
Usage:
  scripts/realdata_campaign.sh --out-root DIR --cwe CWE-120|CWE-121 \
      [--primevul JSONL] [--secvuleval PARQUET] [--data-root DIR] \
      [--profile JSON] [--limit N] [--timeout SEC] [--fetch-registered-pilot] \
      [--prepare-only] [--hidden-root DIR] [--hidden-key-env ENV_NAME]

At least one input dataset is required. --fetch-registered-pilot fetches the pinned
PrimeVul test artifact and registered SecVulEval train artifact as an ingestion pilot;
it does NOT create an independent publication-grade hidden evaluation set.
Without --prepare-only, a working `joern` executable must be on PATH.
EOF
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

while (($#)); do
  case "$1" in
    --cwe) CWE="${2:?}"; shift 2 ;;
    --primevul) PRIMEVUL="${2:?}"; shift 2 ;;
    --secvuleval) SECVULEVAL="${2:?}"; shift 2 ;;
    --data-root) DATA_ROOT="${2:?}"; shift 2 ;;
    --out-root) OUT_ROOT="${2:?}"; shift 2 ;;
    --profile) PROFILE="${2:?}"; shift 2 ;;
    --limit) LIMIT="${2:?}"; shift 2 ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    --fetch-registered-pilot) FETCH_PILOT=1; shift ;;
    --prepare-only) PREPARE_ONLY=1; shift ;;
    --hidden-root) HIDDEN_ROOT="${2:?}"; shift 2 ;;
    --hidden-key-env) HIDDEN_KEY_ENV="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ "$CWE" == "CWE-120" || "$CWE" == "CWE-121" ]] || fail "supported in-scope CWE values are CWE-120 and CWE-121"
[[ -n "$OUT_ROOT" ]] || fail "--out-root is required"
[[ -f "$PROFILE" ]] || fail "profile not found: $PROFILE"
[[ -f "$ROOT/datasets/registry.json" ]] || fail "run this script from an installed EvidenceLab checkout with datasets/registry.json"

if [[ -d "$OUT_ROOT" ]] && [[ -n "$(find "$OUT_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  fail "output root already exists and is non-empty; choose a fresh --out-root so prior research artifacts are not overwritten: $OUT_ROOT"
fi
mkdir -p "$DATA_ROOT/raw" "$DATA_ROOT" "$OUT_ROOT/reports"

if ((FETCH_PILOT)); then
  if [[ -z "$PRIMEVUL" ]]; then PRIMEVUL="$DATA_ROOT/raw/primevul_test.jsonl"; fi
  if [[ -z "$SECVULEVAL" ]]; then SECVULEVAL="$DATA_ROOT/raw/secvuleval_train.parquet"; fi
  if [[ ! -f "$PRIMEVUL" ]]; then
    echo "Fetching registry-pinned PrimeVul test artifact..."
    set +e
    python -m evidencelab dataset-fetch --id primevul --artifact test-jsonl \
      --registry "$ROOT/datasets/registry.json" --out "$PRIMEVUL" --timeout 600 \
      >"$OUT_ROOT/reports/fetch-primevul.json" 2>&1
    rc=$?
    set -e
    ((rc == 0)) || { cat "$OUT_ROOT/reports/fetch-primevul.json" >&2; fail "PrimeVul fetch failed (exit $rc)"; }
  fi
  if [[ ! -f "$SECVULEVAL" ]]; then
    echo "Fetching registry-pinned SecVulEval train artifact..."
    set +e
    python -m evidencelab dataset-fetch --id secvuleval --artifact train-parquet \
      --registry "$ROOT/datasets/registry.json" --out "$SECVULEVAL" --timeout 600 \
      >"$OUT_ROOT/reports/fetch-secvuleval.json" 2>&1
    rc=$?
    set -e
    ((rc == 0)) || { cat "$OUT_ROOT/reports/fetch-secvuleval.json" >&2; fail "SecVulEval fetch failed (exit $rc)"; }
  fi
fi

[[ -n "$PRIMEVUL" || -n "$SECVULEVAL" ]] || fail "provide --primevul and/or --secvuleval, or use --fetch-registered-pilot"
[[ -z "$PRIMEVUL" || -f "$PRIMEVUL" ]] || fail "PrimeVul file not found: $PRIMEVUL"
[[ -z "$SECVULEVAL" || -f "$SECVULEVAL" ]] || fail "SecVulEval file not found: $SECVULEVAL"

python -m evidencelab --version || fail "EvidenceLab is not importable from this environment; activate the project's venv and install it"
if [[ -n "$SECVULEVAL" ]]; then
  python - <<'PY' || fail "SecVulEval Parquet requires the optional dependency: python -m pip install -e '.[realdata]'"
try:
    import pyarrow  # noqa: F401
except ImportError:
    raise SystemExit(1)
PY
fi

MANIFESTS=()
if [[ -n "$PRIMEVUL" ]]; then
  manifest="$DATA_ROOT/primevul-${CWE}.manifest.json"
  python -m evidencelab dataset-import-primevul --input "$PRIMEVUL" \
    --out "$manifest" --source-root "$DATA_ROOT/primevul-sources" --cwe "$CWE" \
    >"$OUT_ROOT/reports/import-primevul.json" 2>&1 || { cat "$OUT_ROOT/reports/import-primevul.json" >&2; fail "PrimeVul import failed"; }
  MANIFESTS+=("$manifest")
fi
if [[ -n "$SECVULEVAL" ]]; then
  manifest="$DATA_ROOT/secvuleval-${CWE}.manifest.json"
  python -m evidencelab dataset-import-secvuleval --input "$SECVULEVAL" \
    --out "$manifest" --source-root "$DATA_ROOT/secvuleval-sources" --cwe "$CWE" \
    >"$OUT_ROOT/reports/import-secvuleval.json" 2>&1 || { cat "$OUT_ROOT/reports/import-secvuleval.json" >&2; fail "SecVulEval import failed"; }
  MANIFESTS+=("$manifest")
fi

for manifest in "${MANIFESTS[@]}"; do
  base="$(basename "$manifest" .manifest.json)"
  python "$ROOT/scripts/realdata_manifest_audit.py" --manifest "$manifest" \
    --verify-source-hashes --out "$OUT_ROOT/reports/${base}-census.json" \
    >"$OUT_ROOT/reports/${base}-census.stdout.json" || {
      echo "Manifest census found source/metadata issues; inspect $OUT_ROOT/reports/${base}-census.json" >&2
      fail "metadata/integrity audit failed for $manifest"
    }
  python -m evidencelab dataset-validate --input "$manifest" \
    --require-label-provenance --require-case-identity --require-source-hash \
    >"$OUT_ROOT/reports/${base}-dataset-validate.json" 2>&1 || {
      cat "$OUT_ROOT/reports/${base}-dataset-validate.json" >&2
      fail "EvidenceLab dataset validation failed for $manifest"
    }
done

if ((PREPARE_ONLY)); then
  cat <<EOF
PREPARATION COMPLETE (not a vulnerability evaluation).
Imported manifests:
$(printf '  %s\n' "${MANIFESTS[@]}")
Audit reports: $OUT_ROOT/reports
Next remove --prepare-only to capture source with Joern and evaluate existing patterns.
EOF
  exit 0
fi

command -v joern >/dev/null 2>&1 || fail "Joern is required for capture. Install/configure Joern, or use --prepare-only for import and provenance checks only."

BUILD_ARGS=(research-build --out-dir "$OUT_ROOT/corpus" --cwe "$CWE" --profile "$PROFILE" --timeout "$TIMEOUT")
for manifest in "${MANIFESTS[@]}"; do BUILD_ARGS+=(--input "$manifest"); done
if [[ -n "$LIMIT" ]]; then BUILD_ARGS+=(--limit "$LIMIT"); fi
# A degraded build should still leave its full diagnostic report for inspection.
set +e
python -m evidencelab "${BUILD_ARGS[@]}" >"$OUT_ROOT/reports/research-build.stdout.json" 2>&1
BUILD_RC=$?
set -e
if [[ ! -f "$OUT_ROOT/corpus/benchmark.json" ]]; then
  cat "$OUT_ROOT/reports/research-build.stdout.json" >&2
  fail "research-build did not produce benchmark.json (exit $BUILD_RC)"
fi

if [[ "$CWE" == "CWE-120" ]]; then PATTERN_ROOT="$ROOT/examples/cwe-120/families"; else PATTERN_ROOT="$ROOT/examples/cwe-121/families"; fi
EVAL_ROOT="$OUT_ROOT/evaluation/$CWE"
python "$ROOT/scripts/materialize_corpus_for_research.py" \
  --benchmark "$OUT_ROOT/corpus/benchmark.json" \
  --pattern-root "$PATTERN_ROOT" --out-root "$EVAL_ROOT" \
  --allowed-source-root "$DATA_ROOT" \
  --report "$OUT_ROOT/reports/materialization.json" \
  >"$OUT_ROOT/reports/materialization.stdout.json" || fail "could not materialize corpus for pattern evaluation"

CHECK_ARGS=(research-check --root "$EVAL_ROOT" --profile "$PROFILE" --out "$OUT_ROOT/reports/research-check-metrics.json")
if [[ -n "$HIDDEN_ROOT" ]]; then CHECK_ARGS+=(--hidden-root "$HIDDEN_ROOT"); fi
if [[ -n "$HIDDEN_KEY_ENV" ]]; then CHECK_ARGS+=(--hidden-key-env "$HIDDEN_KEY_ENV"); fi
set +e
python -m evidencelab "${CHECK_ARGS[@]}" >"$OUT_ROOT/reports/research-check-metrics.stdout.json" 2>&1
METRICS_RC=$?
STRICT_ARGS=(research-check --root "$EVAL_ROOT" --profile "$PROFILE" --enforce-gates --require-hidden --out "$OUT_ROOT/reports/research-check-strict.json")
if [[ -n "$HIDDEN_ROOT" ]]; then STRICT_ARGS+=(--hidden-root "$HIDDEN_ROOT"); fi
if [[ -n "$HIDDEN_KEY_ENV" ]]; then STRICT_ARGS+=(--hidden-key-env "$HIDDEN_KEY_ENV"); fi
python -m evidencelab "${STRICT_ARGS[@]}" >"$OUT_ROOT/reports/research-check-strict.stdout.json" 2>&1
STRICT_RC=$?
set -e

cat <<EOF
Real-data campaign completed its configured stages.
  CWE:                 $CWE
  Captured benchmark:  $OUT_ROOT/corpus/benchmark.json
  Evaluation tree:     $EVAL_ROOT
  Build exit:          $BUILD_RC
  Metrics exit:        $METRICS_RC
  Strict-gate exit:    $STRICT_RC
  Reports:             $OUT_ROOT/reports

A failed strict-gate result is not suppressed: inspect research-check-strict.json.
The publication profile intentionally requires adequate independent data and an
externally-originated sealed hidden validation bundle; the registered pilot download
alone cannot satisfy those requirements. This script does not relabel failures as passes.
EOF
exit "$STRICT_RC"
