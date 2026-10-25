#!/usr/bin/env bash
# EvidenceLab live evaluation. Read-only with respect to the repository.
set -uo pipefail
umask 077

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="/tmp/evidencelab-live-evaluation-$STAMP"
mkdir -p "$OUT/logs" "$OUT/scans"
REPORT="$OUT/report.md"
STATUS="$OUT/command-status.tsv"
printf 'check\tstatus\tdetails\n' > "$STATUS"

# Timeouts are intentionally finite so a stuck Joern process cannot block forever.
VALIDATOR_TIMEOUT="${VALIDATOR_TIMEOUT:-90}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-300}"
DATAFLOW_TIMEOUT="${DATAFLOW_TIMEOUT:-180}"
SLICE_DEPTH="${SLICE_DEPTH:-4}"

run_cmd() {
    local name="$1"; shift
    local logfile="$OUT/logs/$name.log"
    local rc=0
    {
        printf 'COMMAND:'
        printf ' %q' "$@"
        printf '\nSTART: %s\n' "$(date -Is)"
    } > "$logfile"

    # GNU timeout is available on standard Ubuntu. If missing, fail safely.
    if ! command -v timeout >/dev/null 2>&1; then
        echo "GNU timeout utility not found; command not run." >> "$logfile"
        rc=127
    else
        timeout --signal=INT --kill-after=15s "${VALIDATOR_TIMEOUT}s" \
            "$@" >> "$logfile" 2>&1 || rc=$?
    fi
    printf 'END: %s\nEXIT_CODE: %s\n' "$(date -Is)" "$rc" >> "$logfile"
    printf '%s\t%s\t%s\n' "$name" "$rc" "logs/$name.log" >> "$STATUS"
    return 0
}

run_scan() {
    local label="$1"
    local source="$2"
    local outdir="$OUT/scans/$label"
    local logfile="$OUT/logs/scan-$label.log"
    local rc=0
    mkdir -p "$outdir"

    {
        printf 'COMMAND: timeout --signal=INT --kill-after=20s %q python -m evidencelab scan' "${SCAN_TIMEOUT}s"
        printf ' --source %q --pattern %q --out %q --dataflow-timeout %q --dataflow-slice-depth %q\n' \
            "$source" "$PATTERN" "$outdir" "$DATAFLOW_TIMEOUT" "$SLICE_DEPTH"
        printf 'START: %s\n' "$(date -Is)"
    } > "$logfile"

    timeout --signal=INT --kill-after=20s "${SCAN_TIMEOUT}s" \
        python -m evidencelab scan \
        --source "$source" \
        --pattern "$PATTERN" \
        --out "$outdir" \
        --dataflow-timeout "$DATAFLOW_TIMEOUT" \
        --dataflow-slice-depth "$SLICE_DEPTH" \
        >> "$logfile" 2>&1 || rc=$?

    printf 'END: %s\nEXIT_CODE: %s\n' "$(date -Is)" "$rc" >> "$logfile"
    printf 'scan-%s\t%s\tlogs/scan-%s.log\n' "$label" "$rc" "$label" >> "$STATUS"
    return 0
}

cat > "$REPORT" <<EOF
# EvidenceLab Live Evaluation Report

- Timestamp: $(date -Is)
- Repository root: $ROOT
- Branch: $(git branch --show-current 2>/dev/null || echo unknown)
- HEAD: $(git log -1 --format='%h %s' 2>/dev/null || echo unknown)
- Python: $(python --version 2>&1)
- Environment: $(python -c 'import sys; print(sys.executable)' 2>/dev/null || echo unknown)

## Purpose and limits

This run validates the local corpus, checks its recorded SHA-256 hashes, and attempts three live scans using the CWE-121 unbounded-copy pattern.
It does not prove general safety and does not evaluate all 69 samples or all 23 CWE families.
Scan exit codes are operational results, not security verdicts.

EOF

{
    echo "## 1. Repository state"
    echo
    echo '```text'
    git status --short --branch 2>&1 || true
    echo
    git log -1 --oneline --decorate 2>&1 || true
    echo '```'
    echo
    echo "## 2. Runtime and tool availability"
    echo
    echo '```text'
    python --version 2>&1 || true
    python -m evidencelab --version 2>&1 || true
    for t in joern joern-parse joern-export java timeout; do
        if command -v "$t" >/dev/null 2>&1; then
            printf '%s: %s\n' "$t" "$(command -v "$t")"
        else
            printf '%s: NOT FOUND\n' "$t"
        fi
    done
    echo '```'
    echo
} >> "$REPORT"

CORPUS="examples/c-security-corpus"
VALIDATOR="$CORPUS/tools/validate_corpus.py"
SUMS="$CORPUS/metadata/SHA256SUMS"
PATTERN="examples/cwe-121/families/unbounded-copy/pattern.json"

echo "## 3. Corpus validation" >> "$REPORT"
echo >> "$REPORT"
if [[ -f "$VALIDATOR" ]]; then
    # Run from repo root; the validator may expect a relative corpus path.
    run_cmd "corpus-validator" python "$VALIDATOR"
else
    printf 'corpus-validator\tSKIPPED\tvalidator not found: %s\n' "$VALIDATOR" >> "$STATUS"
    echo "Validator not found: \`$VALIDATOR\`." > "$OUT/logs/corpus-validator.log"
fi

if [[ -f "$SUMS" ]]; then
    (
        cd "$CORPUS" &&
        sha256sum -c metadata/SHA256SUMS
    ) > "$OUT/logs/corpus-sha256.log" 2>&1
    rc=$?
    printf 'corpus-sha256\t%s\tlogs/corpus-sha256.log\n' "$rc" >> "$STATUS"
else
    rc=127
    echo "SHA256SUMS not found: $SUMS" > "$OUT/logs/corpus-sha256.log"
    printf 'corpus-sha256\t%s\tlogs/corpus-sha256.log\n' "$rc" >> "$STATUS"
fi

{
    echo '### Corpus validator output'
    echo
    echo '```text'
    cat "$OUT/logs/corpus-validator.log" 2>/dev/null || true
    echo '```'
    echo
    echo "### SHA-256 verification (exit code: $rc)"
    echo
    echo '```text'
    cat "$OUT/logs/corpus-sha256.log"
    echo '```'
    echo
} >> "$REPORT"

echo "## 4. Live scan runs" >> "$REPORT"
echo >> "$REPORT"

if [[ ! -f "$PATTERN" ]]; then
    printf 'live-scans\tSKIPPED\tpattern not found: %s\n' "$PATTERN" >> "$STATUS"
    echo "Pattern not found: \`$PATTERN\`. Live scans were skipped." >> "$REPORT"
elif ! command -v joern >/dev/null 2>&1; then
    printf 'live-scans\tSKIPPED\tjoern executable not found\n' >> "$STATUS"
    echo "Joern executable not found on PATH; live scans were skipped." >> "$REPORT"
else
    declare -a labels=("VULN" "SAFE" "UNKNOWN")
    declare -a sources=(
        "$CORPUS/samples/stack-buffer-overflow/vuln/V01_unbounded_copy.c"
        "$CORPUS/samples/stack-buffer-overflow/safe/S01_bounded_copy.c"
        "$CORPUS/samples/stack-buffer-overflow/unknown/U01_external_capacity.c"
    )

    for i in "${!labels[@]}"; do
        label="${labels[$i]}"
        source="${sources[$i]}"
        echo "Running $label: $source"
        if [[ ! -f "$source" ]]; then
            printf 'scan-%s\tSKIPPED\tsource file not found: %s\n' "$label" "$source" >> "$STATUS"
            echo "### $label: SKIPPED" >> "$REPORT"
            echo "Source not found: \`$source\`." >> "$REPORT"
            echo >> "$REPORT"
            continue
        fi
        run_scan "$label" "$source"
        echo "### $label" >> "$REPORT"
        echo >> "$REPORT"
        echo "- Source: \`$source\`" >> "$REPORT"
        echo "- Output directory: \`scans/$label\`" >> "$REPORT"
        echo "- Full CLI log: \`logs/scan-$label.log\`" >> "$REPORT"
        echo >> "$REPORT"
        echo '```text' >> "$REPORT"
        tail -n 70 "$OUT/logs/scan-$label.log" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo >> "$REPORT"
    done
fi

echo "## 5. Extracted scan artifacts" >> "$REPORT"
echo >> "$REPORT"
echo "The scan directories are preserved in full. The following inventory lists produced files:" >> "$REPORT"
echo >> "$REPORT"
echo '```text' >> "$REPORT"
find "$OUT/scans" -type f -printf '%P (%s bytes)\n' 2>/dev/null | sort >> "$REPORT" || true
echo '```' >> "$REPORT"
echo >> "$REPORT"

# Extract verdict-like JSON fields from any JSON artifact without assuming a single schema.
python - "$OUT" >> "$REPORT" <<'PY'
import json, sys
from pathlib import Path

root = Path(sys.argv[1])
print("### JSON artifact summary")
print()
found = 0
interesting = {
    "status", "verdict", "outcome", "result", "pattern_id",
    "analysis_incomplete", "graph_complete_for_absence",
    "witness_search_complete", "analyzer_attestation",
    "capture_status", "dataflow_status", "claims_replayed",
    "proved_claims", "disproved_claims", "unknown_claims",
}
for path in sorted((root / "scans").rglob("*.json")):
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    found += 1
    print(f"- File: `{path.relative_to(root)}`")
    if isinstance(obj, dict):
        # Recursively collect only selected, useful keys.
        matches = []
        def walk(x, prefix=""):
            if isinstance(x, dict):
                for k, v in x.items():
                    p = f"{prefix}.{k}" if prefix else k
                    if k in interesting:
                        try:
                            val = json.dumps(v, ensure_ascii=False)
                        except Exception:
                            val = repr(v)
                        matches.append((p, val[:600]))
                    walk(v, p)
            elif isinstance(x, list):
                for i, v in enumerate(x[:100]):
                    walk(v, f"{prefix}[{i}]")
        walk(obj)
        for key, val in matches[:35]:
            print(f"  - `{key}`: `{val}`")
    print()
if not found:
    print("No parseable JSON artifacts found. Inspect full logs and scan output directories.")
    print()
PY

{
    echo "## 6. Command status table"
    echo
    echo '```text'
    cat "$STATUS"
    echo '```'
    echo
    echo "## 7. Interpretation checklist"
    echo
    echo "- Treat scan timeout or CLI failure as an incomplete run, not as a security verdict."
    echo "- Compare the three verdicts with the actual pattern and trace; do not infer global safety from SAFE/NO_MATCH."
    echo "- For UNKNOWN, inspect the required selector slot, semantic classification, graph completeness, trace, and attestation."
    echo "- Report any unexpected result; this harness does not automatically label it a confirmed bug."
    echo
} >> "$REPORT"

cp "$STATUS" "$OUT/command-status.tsv"

ARCHIVE="/tmp/$(basename "$OUT").zip"
(
    cd "$(dirname "$OUT")" &&
    zip -qr "$ARCHIVE" "$(basename "$OUT")"
)

echo
echo "Live evaluation completed."
echo "Report:  $REPORT"
echo "Archive: $ARCHIVE"
echo "Upload the ZIP archive for review."
