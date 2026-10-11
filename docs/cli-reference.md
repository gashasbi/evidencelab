# Command-line reference

Use `python -m evidencelab` for the same CLI entry point that is installed as `evidencelab`. The command forms below assume the virtual environment is active and the current directory is the repository root. Every command supports `--help`; its runtime help is the authoritative list of accepted arguments in the installed version.

## Global commands

```bash
python -m evidencelab --version
python -m evidencelab --help
python -m evidencelab <command> --help
```

## Installation and environment

| Command | Purpose | Common use |
|---|---|---|
| `doctor` | Report Python and detectable Joern capabilities. | `python -m evidencelab doctor`; add `--joern` for Joern-specific diagnostics. |
| `init` | Create a researcher workspace for a CWE. | `python -m evidencelab init --cwe CWE-121 --out research/cwe-121`. |
| `research-init` | Initialize a research project workspace. | `python -m evidencelab research-init --cwe CWE-121 --out research/cwe-121`. |
| `family-init` | Add an Evidence Family in an existing research project. | Use `--research-root`, `--family-id`, and optionally `--name` and `--research-question`. |

## Evidence definitions and graph artifacts

| Command | Purpose | Key arguments |
|---|---|---|
| `evidence validate` | Parse and validate an ELS definition. | `--spec FILE` |
| `evidence compile` | Compile ELS into a public Evidence Pattern artifact. | `--spec FILE --out FILE` |
| `evidence ir` | Emit the compiled/intermediate representation. | `--spec FILE --out FILE` |
| `evidence run` | Execute ELS against a canonical graph. | `--spec FILE --graph FILE [--out FILE] [--audit]` |
| `evidence-validate` | Alias for ELS validation. | `--input FILE` or `--spec FILE` |
| `evidence-compile` | Alias for ELS compilation. | `--input FILE` or `--spec FILE`, plus `--out FILE` |
| `evidence-test` | Alias for ELS execution. | `--evidence FILE` or `--spec FILE`, `--graph FILE` |
| `audit` | Audit an Evidence Pattern. | `--pattern FILE [--profile FILE] [--json]` |
| `inspect` | Inspect a graph and optionally its details. | `--graph FILE [--detailed] [--strict]` |
| `normalize` | Normalize one graph artifact to the canonical graph format. | `--graph FILE --out FILE [--pretty]` |
| `merge` | Merge two or more supported graph artifacts. Repeat `--graph`. | `--graph FILE --graph FILE --out FILE [--pretty]` |
| `migrate-pattern` | Normalize an imported Evidence Pattern to schema 1.0. | `--pattern FILE --out FILE [--family-id ID]`; researcher review is mandatory. |
| `schema-check` | Validate JSON against a selected JSON Schema. | `--input FILE --schema FILE` |
| `cwe sync` | Refresh a local CWE catalog artifact. | `python -m evidencelab cwe sync [--out FILE]` |
| `cwe show` | Display a CWE entry from a local catalog. | `--catalog FILE --cwe CWE-121` |

Example ELS workflow:

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els
python -m evidencelab evidence compile \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --out /tmp/evidence-pattern.json
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/vulnerable.json \
  --out /tmp/evidence-result.json
```

## Joern capture and scanning

| Command | Purpose | Key arguments |
|---|---|---|
| `capture` | Produce Joern CPG and exports for source. | `--source PATH --out DIR`; optional `--no-graphson`, `--no-dataflow`, data-flow timeout/depth/filters, `--best-effort-dataflow`. |
| `scan` | Capture source, merge supported graph artifacts, execute one or more patterns, and replay witnesses. | `--source PATH --out DIR`; repeat `--pattern FILE` or supply `--family-root DIR`. |
| `capture-corpus` | Capture source cases described by a manifest and write a benchmark manifest. | `--manifest FILE --out-dir DIR --benchmark-out FILE`; supports timeout, depth, limit, and best-effort controls. |

See [Joern integration](joern-integration.md) before running a live capture. It specifies external executables, artifact layout, and how to interpret degraded analysis.

## Pattern, benchmark, and submission validation

| Command | Purpose | Key arguments |
|---|---|---|
| `validate` | Validate a pattern against a graph or benchmark and produce reports. | `--pattern FILE`; one of `--graph` or `--benchmark` as applicable; optional `--profile`, `--format`, `--out`, `--report-dir`, hidden-case controls. |
| `benchmark-audit` | Audit a benchmark against a pattern. | `--benchmark FILE --pattern FILE [--json]` |
| `benchmark-quality` | Check benchmark size/class minimums and profile rules. | `--benchmark FILE`; configurable minimum case and label counts. |
| `benchmark-plan` | Produce a benchmark plan from a profile. | `--benchmark FILE --profile FILE [--out FILE]` |
| `benchmark-compose` | Compose multiple manifests into one benchmark. Repeat `--input`. | `--input FILE ... --out FILE`; controls for graph copying, conflicts, and unknown cases. |
| `benchmark-split` | Separate public and hidden cases. | `--manifest FILE --public-out FILE --hidden-out FILE`; fraction and deterministic seed options. |
| `hidden-seal` | Create a sealed hidden-benchmark bundle. | `--benchmark FILE --out DIR`; optional HMAC key environment variable and origin setting. |
| `hidden-verify` | Verify a sealed bundle. | `--bundle DIR`; optional HMAC and external-origin enforcement. |
| `make-submission` | Create a submission manifest for a research task. | `--root DIR --cwe CWE --pattern FILE --graph FILE ...` |
| `validate-submission` | Validate a submission against a profile and optional hidden benchmark. | `--submission FILE [--profile FILE] [--hidden-benchmark FILE]` |
| `witness-validate` | Validate witness artifacts in a report or benchmark. | `--report FILE` or benchmark/pattern arguments; optional limits and expected-outcome selector. |
| `witness-replay` | Independently replay one stored fixed-binding witness. | `--report FILE --graph FILE --pattern FILE` |
| `witness-replay-batch` | Replay stored evaluation case reports without rerunning candidate search. | `--results-dir DIR --pattern FILE` |
| `performance` | Repeat benchmark evaluation and record performance measurements. | `--benchmark FILE --pattern FILE`; optional repetitions, partition, and per-case time bound. |

## Research workspace, ledgers, and readiness

| Command | Purpose | Key arguments |
|---|---|---|
| `research-check` | Check research package contracts and optional profile gates. | `--root DIR`; optional `--profile`, hidden-root/key, `--enforce-gates`, `--require-hidden`, `--summary`, `--out`. |
| `research-readiness` | Produce an actionable readiness report. | `--root DIR --profile FILE`; optional hidden root and output. |
| `research-audit` | Audit ledgers, package completeness, and hidden-benchmark requirements. | `--root DIR [--require-hidden] [--out FILE]` |
| `research-evaluate` | Run and persist an evaluation across the configured research package. | `--root DIR --profile FILE`; optional output, hidden root/key, and gate enforcement. |
| `evaluate-benchmark` | Evaluate one benchmark and write per-case artifacts. | `--benchmark FILE --pattern FILE --out DIR`; optional partition, replay, and performance repeats. |
| `research-build` | Build an auditable corpus from one or more external dataset manifests. | Repeat `--input FILE`; use `--out-dir DIR`; optional CWE/profile/limit/capture/split controls. |
| `research-status` | Print compact project/family/benchmark/ledger status. | `--root DIR [--profile FILE] [--hidden-root DIR]` |
| `research-record` | Append an experiment record. | `--root DIR --hypothesis TEXT --tool NAME --command TEXT --result TEXT` |
| `observation-record` | Append a provenance-linked raw observation. | `--root DIR --analyzer NAME`; supply query/artifact/statement/state/location/digest as applicable. |
| `derivation-record` | Append a provenance-linked semantic derivation. | `--root DIR --method TEXT --output JSON`; identify inputs and assumptions. |
| `research-inventory` | Hash a research workspace for reproducibility. | `--root DIR --out FILE`; hidden and external data are opt-in flags. |
| `research-inventory-verify` | Verify a stored research inventory. | `--manifest FILE` |
| `research-bundle` | Create a reproducibility `.tar.gz` bundle. | `--root DIR --out FILE`; hidden/external data inclusion is explicit. |
| `placeholder-audit` | Detect unfinished executable pattern templates. | `--root DIR [--allow-scaffold]` |
| `provenance-index` | Create a cryptographic artifact inventory. | `--root DIR --out FILE [--activity LABEL]` |
| `provenance-verify` | Verify a provenance manifest. | `--manifest FILE` |

## Corpora, splits, leakage, and lineage

| Command | Purpose | Key arguments |
|---|---|---|
| `corpus-inventory` | Inventory a source tree. | `--root DIR --out FILE` |
| `corpus-tags` | Create a tag matrix from a corpus/benchmark manifest. | `--manifest FILE [--out FILE]` |
| `coverage-matrix` | Summarize evidence-dimension/label coverage. | `--manifest FILE [--out FILE]` |
| `split` | Create a grouped train/validation/test split. | `--manifest FILE --out-dir DIR`; strategy `repository`, `project`, `cve`, or `mutation`; ratios and seed configurable. |
| `split-chronological` | Split by recorded time order. | `--manifest FILE --out-dir DIR`; configure train/validation shares and missing-date policy. |
| `split-audit` | Audit split manifests for cross-partition leakage. | `--dir DIR [--strategy NAME]` |
| `leakage-audit` | Compare source files for near-duplicate or mutation leakage. | Repeat `--source FILE`; configure similarity threshold and maximum comparisons. |
| `leakage-audit-manifest` | Audit leakage from a benchmark manifest. | `--benchmark FILE`; optional threshold and comparison limit. |
| `lineage-audit` | Audit source/mutation/commit lineage in a benchmark. | `--benchmark FILE [--out FILE]` |
| `mutate` | Apply declared mutation recipes to source material. | `--source FILE --recipes FILE --out-dir DIR` |
| `git-pair` | Build a before/after pair from a repository and fixed commit. | `--repo DIR --fixed-commit SHA --cwe CWE --out FILE [--cve ID]` |

## Dataset acquisition and import

| Command | Purpose | Key arguments |
|---|---|---|
| `dataset-registry` | Print the configured dataset registry. | `[--file datasets/registry.json]` |
| `dataset-fetch` | Fetch an artifact declared by the registry. | `--id ID --out PATH`; optional artifact ID, registry, timeout, maximum bytes, and resume control. |
| `fetch` | Fetch a URL to a local path with optional digest verification. | `--url URL --out PATH [--sha256 DIGEST]` plus size and timeout controls. |
| `dataset-index-archive` | Inventory a dataset archive. | `--archive FILE --out FILE` |
| `dataset-validate` | Validate a dataset manifest's identity and provenance. | `--input FILE`; optional required checks for label provenance, case identity, and source hashes. |
| `dataset-import-sard` | Import supported SARD input material. | `--input FILE --out FILE`; optional CWE and source root. |
| `dataset-import-juliet` | Import a Juliet source tree. | `--root DIR --out FILE`; optional CWE, partition, source-copying, and label mode. |
| `dataset-import-primevul` | Import supported PrimeVul JSONL records. | `--input FILE --out FILE --source-root DIR [--cwe CWE]` |
| `dataset-import-secvuleval` | Import supported SecVulEval JSONL records. | `--input FILE --out FILE --source-root DIR [--cwe CWE]` |
| `dataset-import-diversevul` | Import supported DiverseVul JSONL records. | `--input FILE --out FILE --source-root DIR [--cwe CWE]` |
| `dataset-merge` | Merge dataset manifests. | Repeat `--input FILE`; set `--out FILE`. |
| `dataset-model-validate` | Validate a researcher-defined mapping. | `--model FILE` |
| `dataset-model-preview` | Preview materialization without running analysis. | `--model FILE [--limit N]` |
| `dataset-model-import` | Materialize a canonical experimental-material manifest. | `--model FILE --out FILE` |

The presence of an importer is not a statement that EvidenceLab distributes the corresponding dataset, endorses its labels, or has tested every upstream release. Record the exact source version and hashes; consult [Dataset integration](dataset-integration.md) and the [real-world runbook](real-world-runbook.md).

## SARIF and TEF

| Command | Purpose | Key arguments |
|---|---|---|
| `sarif-ingest` | Parse SARIF into a supported graph/observation representation. | `--input FILE --out FILE` |
| `sarif` | Write a matcher/evaluation report in SARIF form. | `--report FILE --out FILE` |
| `tef-validate` | Validate a TEF document. | `--input FILE [--out FILE]`; requires YAML support for YAML inputs. |
| `tef-normalize` | Normalize a TEF document into EvidenceLab notes/artifact form. | `--input FILE --out FILE` |

## JSON output and repeatability recommendations

1. Keep command lines and tool versions with the result.
2. Use absolute, project-local paths for material mappings and avoid path escapes.
3. Keep raw source and analyzer exports when generating derived canonical graphs.
4. Use explicit `--out` paths for machine-readable artifacts; do not rely on terminal text as the only research record.
5. Preserve return codes, `status`, analysis completeness, witness replay, and warnings independently.
6. Verify manifests after copying or transferring artifacts.
7. Read the full `--help` output for an option before scripting it against another release.
