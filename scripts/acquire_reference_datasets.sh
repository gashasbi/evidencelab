#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${EVIDENCELAB_PYTHON:-}"
if [[ -z "$PYTHON" && -x "$ROOT/.venv/bin/python" ]]; then PYTHON="$ROOT/.venv/bin/python"; fi
if [[ -z "$PYTHON" ]]; then PYTHON="$(command -v python3)"; fi
OUT="${1:-$ROOT/datasets/raw}"
mkdir -p "$OUT"

echo "[EvidenceLab] acquiring pinned reference datasets into: $OUT"
"$PYTHON" -m evidencelab dataset-fetch --id nist-juliet-c-cpp-1.3 --registry "$ROOT/datasets/registry.json" --out "$OUT/juliet-c-cpp-1.3.zip"
"$PYTHON" -m evidencelab dataset-fetch --id nist-sate6-wireshark --registry "$ROOT/datasets/registry.json" --out "$OUT/sate6-wireshark-1.2.zip"
"$PYTHON" -m evidencelab dataset-fetch --id primevul --artifact test-jsonl --registry "$ROOT/datasets/registry.json" --out "$OUT/primevul-test.jsonl"
"$PYTHON" -m evidencelab dataset-fetch --id primevul --artifact test-paired-jsonl --registry "$ROOT/datasets/registry.json" --out "$OUT/primevul-test-paired.jsonl"
"$PYTHON" -m evidencelab dataset-fetch --id secvuleval --artifact train-parquet --registry "$ROOT/datasets/registry.json" --out "$OUT/secvuleval-train.parquet"

echo "[EvidenceLab] acquisition complete. Acquisition records are stored next to each artifact."
