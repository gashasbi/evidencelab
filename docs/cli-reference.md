# Command-line reference

Run commands from the repository root with the intended virtual environment active. The installed console command `evidencelab` and `python -m evidencelab` use the same CLI entry point.

The runtime help is authoritative for the installed checkout:

```bash
python -m evidencelab --version
python -m evidencelab --help
python -m evidencelab COMMAND --help
```

The CLI has many subcommands; this page groups the main workflows rather than duplicating every argument. Consult each command's `--help` before automating it.

## Environment and workspaces

| Command | Purpose |
|---|---|
| `doctor` | Report detectable Python and optional Joern capabilities. |
| `init` / `research-init` | Initialize a research workspace. |
| `family-init` | Add an Evidence Family to a research project. |

Examples:

```bash
python -m evidencelab doctor
python -m evidencelab doctor --joern
python -m evidencelab research-init --cwe CWE-121 --out research/cwe-121
```

## Evidence and graphs

| Command | Purpose |
|---|---|
| `evidence validate` | Validate an ELS definition. |
| `evidence compile` | Compile ELS into a Pattern artifact. |
| `evidence ir` | Emit an intermediate representation. |
| `evidence run` | Evaluate a definition against a graph. |
| `audit` | Audit a Pattern, optionally against a profile. |
| `inspect` | Inspect a graph artifact. |
| `normalize` | Normalize a supported graph to the canonical representation. |
| `merge` | Merge supported graph artifacts. |
| `migrate-pattern` | Normalize a supported Pattern to the current schema contract. |
| `schema-check` | Validate JSON against a schema. |

## Source analysis and scanning

| Command | Purpose |
|---|---|
| `capture` | Invoke Joern to capture and export artifacts for a source path. |
| `scan` | Capture source, merge graph inputs, run patterns, and preserve reports where supported. |
| `capture-corpus` | Capture cases from a source manifest and write a benchmark manifest. |

These workflows require the external Joern tools described in [Joern integration](joern-integration.md). A successful process is not proof that every relevant semantic relation was recovered.

## Benchmarks and evaluation

| Command | Purpose |
|---|---|
| `validate` | Validate a Pattern against a graph or benchmark. |
| `benchmark-audit` / `benchmark-quality` | Check benchmark structure and configured quality constraints. |
| `benchmark-plan` / `benchmark-compose` | Plan or combine benchmark manifests. |
| `benchmark-split` / `split` / `split-chronological` | Create benchmark partitions. |
| `split-audit` | Audit partitioning for leakage. |
| `evaluate-benchmark` / `research-evaluate` | Evaluate a Pattern on benchmark or research-package material. |
| `performance` | Record repeated evaluation measurements. |
| `witness-validate` / `witness-replay` / `witness-replay-batch` | Validate or replay stored witness artifacts. |

## Research records and provenance

| Command | Purpose |
|---|---|
| `research-check` / `research-readiness` / `research-audit` | Check research package contracts and readiness. |
| `research-record` | Append an experiment record. |
| `observation-record` / `derivation-record` | Record provenance-linked observations and derived facts. |
| `research-inventory` / `research-inventory-verify` | Create or verify a research inventory. |
| `provenance-index` / `provenance-verify` | Index and verify artifact digests. |
| `research-bundle` | Create a reproducibility bundle. |
| `placeholder-audit` | Find unfinished executable templates. |

## Dataset and format integration

| Command | Purpose |
|---|---|
| `dataset-registry` / `dataset-fetch` / `fetch` | Inspect a registry or fetch declared material. |
| `dataset-index-archive` / `dataset-validate` | Inventory or validate dataset artifacts. |
| `dataset-import-juliet` / `dataset-import-sard` | Import supported Juliet or SARD input forms. |
| `dataset-import-primevul` / `dataset-import-secvuleval` / `dataset-import-diversevul` | Import supported JSONL forms. |
| `dataset-model-validate` / `dataset-model-preview` / `dataset-model-import` | Validate, preview, and materialize declarative mappings. |
| `dataset-merge` | Merge dataset manifests. |
| `sarif-ingest` / `sarif` | Ingest SARIF or write a report in SARIF form. |
| `tef-validate` / `tef-normalize` | Validate or normalize TEF documents; YAML inputs require the `tef` extra. |

Importer availability does not mean the associated dataset is bundled or that every upstream release has been tested. See [Dataset integration](dataset-integration.md).

## Exit codes and reports

For `evidence run`, the current CLI returns exit code `0` for `MATCH` and `1` for other outcomes, including `NO_MATCH`, `PARTIAL`, and `UNKNOWN`. Inspect the report's `status`, trace, warnings, and completeness fields before deciding whether a nonzero code indicates an expected result or an operational failure.

For shell automation, handle expected non-`MATCH` outcomes explicitly, especially when using `set -e`. Prefer saving machine-readable reports with `--out`; retain commands, tool versions, return codes, and warnings with research records.
