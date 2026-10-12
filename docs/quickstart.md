# Quickstart

This walkthrough runs the bundled ELS against two already-normalized reference graphs. It does not call Joern or compile source code.

## 1. Check the environment

Run from the repository root with the project installed in the active virtual environment:

```bash
python -m evidencelab --version
python -m evidencelab doctor
```

If the CLI cannot be imported, follow [Installation](installation.md) and [Troubleshooting](troubleshooting.md).

## 2. Validate the Evidence definition

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els
```

This checks the ELS contract. It does not prove that the definition is sufficient for real-world vulnerability detection.

## 3. Run the vulnerable and safe reference graphs

The CLI prints a detailed JSON report. Redirect stdout for a quieter walkthrough; `--out` still saves the report file. **Exit-code note:** `evidence run` exits `0` for `MATCH` and `1` for every other outcome, including the expected `NO_MATCH` on the safe fixture. The JSON report's `status` is the decision; the non-zero exit for `NO_MATCH` is not, by itself, an execution crash.

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/vulnerable.json \
  --out /tmp/evidencelab-vulnerable.json > /dev/null

python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/safe.json \
  --out /tmp/evidencelab-safe.json > /dev/null
```

Print a compact summary:

```bash
python - <<'PY'
import json
from pathlib import Path

for name, path in (
    ("vulnerable", "/tmp/evidencelab-vulnerable.json"),
    ("safe", "/tmp/evidencelab-safe.json"),
):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    trace = report.get("evidence_trace", {})
    print(
        name,
        "status=" + str(report.get("status")),
        "incomplete=" + str(trace.get("analysis_incomplete")),
        "search_complete=" + str(trace.get("witness_search_complete")),
    )
```

For the bundled fixtures, the expected statuses are `MATCH` for the vulnerable graph and `NO_MATCH` for the safe graph. Both should have a complete search and no incomplete-analysis flag. These are small reference examples, not independent benchmark results.

## What the result means

`MATCH` means the required claims were satisfied by a coherent witness. `NO_MATCH` means no witness satisfied the definition on an input complete enough for that decision. If the report indicates incomplete analysis, truncation, or `UNKNOWN`, do not treat it as a safe result. Read [Evidence model](evidence-model.md) before interpreting a non-match as absence.

## Next step

- To author definitions, read [ELS reference](evidence-dsl.md).
- To import data, use [Dataset integration](dataset-integration.md).
- To analyze source code, prepare Joern using [Joern integration](joern-integration.md).
- To design an evaluation, use [Research methodology](research-methodology.md) and [Benchmark design](benchmark-design.md).
