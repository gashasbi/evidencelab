# EvidenceLab: real-data corpus and independent-validation campaign

## Objective and boundaries

This campaign strengthens the current EvidenceLab research workflow for the already-supported C/C++ CWE-120 and CWE-121 evidence families. It uses the existing dataset importers, Joern capture, benchmark composer, family patterns, witness replay, quality gates, and research-check pipeline. It does not create another source-code analyzer, redefine the meaning of `MATCH`/`NO_MATCH`/`UNKNOWN`, add new CWEs, or weaken the publication profile to make a run appear successful.

The goal is to make it possible to run existing definitions on real external source code, preserve provenance, identify data-quality and integration failures, and produce both exploratory metrics and a separate strict-gate result. The pack deliberately does not bundle upstream datasets. Dataset releases can be large, may have license or redistribution conditions, and may change over time.

## Contents installed by this pack

- `evidencelab/datasets.py`: handle Parquet as binary input before attempting text decoding; preserve imported source code exactly so the saved source bytes agree with the recorded source hash.
- `evidencelab/benchmark_quality.py`: normalize dimension aliases consistently when supplied in either `tags` or `dimensions`; don't treat a generic label-source field as proof of a vulnerability's issue/patch identity.
- `evidencelab/research_pipeline.py`: fix source path roots when a manifest is staged for CWE filtering, and normalize source references in captured manifests relative to the final composed corpus root.
- `tests/test_realdata_quality_hardening.py`: add regressions for those behaviors.
- `scripts/realdata_manifest_audit.py`: make a metadata-only census and optional source SHA-256 check without printing source code.
- `scripts/materialize_corpus_for_research.py`: copy captured graph/source files into an evaluation tree for each existing pattern family and rewrite paths only, allowing the existing `research-check` command to evaluate the same corpus against each existing pattern.
- `scripts/realdata_campaign.sh`: orchestrate import, provenance checks, Joern capture, corpus construction, pattern evaluation, and separate non-strict/strict reports.

## Preconditions

Use a clean checkout of EvidenceLab (the pack was authored against the repository state whose main commit is `e4e10cacd5aec0d0b1f69ea5d5ab7610a9bfed13`). The installer checks expected source anchors and refuses to replace pre-existing installed files with different contents. If your checkout has newer or locally modified versions of these source files, review the source differences instead of forcing the pack onto them.

Create and activate the project's virtual environment. Install the package and test dependency as the project specifies. For the SecVulEval Parquet importer, install the optional data dependency:

```bash
python -m pip install -e '.[dev,realdata]'
python -m evidencelab --version
```

A full capture/evaluation run also requires a working `joern` executable on `PATH`. Test its availability explicitly:

```bash
command -v joern
```

Joern is an external analyzer and is not installed by the Python package. If it is not configured, use `--prepare-only` to perform dataset import and provenance checks, then stop; do not label that as a completed vulnerability evaluation.

## Install the pack

From the downloaded ZIP, unpack it into a temporary directory, then apply it to the existing repository checkout. For example:

```bash
unzip evidencelab-realdata-validation-pack.zip -d /tmp/evidencelab-realdata-pack
python /tmp/evidencelab-realdata-pack/evidencelab-realdata-validation-pack/apply_pack.py ~/projects/evidencelab/evidencelab-clean
```

Change the target path to your own checkout. The installer requires a clean Git worktree by default. It creates timestamped copies of modified source files in a sibling directory named `.<checkout-name>-evidencelab-pack-backup/`, outside the Git worktree; added files are not allowed to overwrite files with different contents.

Then, inside the project checkout:

```bash
python -m py_compile evidencelab/datasets.py evidencelab/benchmark_quality.py evidencelab/research_pipeline.py
python -m pytest -q tests/test_realdata_quality_hardening.py
python scripts/run_isolated_tests.py --timeout 180
```

The first test command validates the new focused regressions; the isolated runner executes the existing suite file-by-file. Joern-dependent tests may still require a working external Joern installation, and the test runner's results must be read rather than assumed.

## Choose real data deliberately

The registry contains pinned pilot artifacts for PrimeVul and SecVulEval. The included `--fetch-registered-pilot` option can fetch those artifacts through EvidenceLab's `dataset-fetch` path, which uses the registry metadata and recorded SHA-256 values. The PrimeVul artifact is the registered test JSONL; the registered SecVulEval artifact is a training Parquet split. They are useful for exercising import/capture code paths, but do not constitute a pre-approved independent held-out test set when combined. Review dataset release notes, split provenance, license, overlap, and study design before drawing an empirical claim.

To use the registered sample artifacts as an ingestion pilot:

```bash
scripts/realdata_campaign.sh \
  --fetch-registered-pilot \
  --cwe CWE-120 \
  --data-root "$HOME/evidencelab-data" \
  --out-root "$HOME/evidencelab-campaign-cwe120" \
  --prepare-only
```

This command downloads and imports the pinned sample artifacts, checks source paths and hashes, runs EvidenceLab's dataset validation, and stops before Joern capture. The script retains logs under the requested output root. The pilot may fail a validation check if upstream metadata or source hashes do not satisfy current project contracts; investigate the report instead of changing labels or weakening gates.

To run all enabled steps, remove `--prepare-only` and configure Joern:

```bash
scripts/realdata_campaign.sh \
  --fetch-registered-pilot \
  --cwe CWE-120 \
  --data-root "$HOME/evidencelab-data" \
  --out-root "$HOME/evidencelab-campaign-cwe120" \
  --timeout 600
```

The script captures every case remaining after the selected-CWE filtering unless `--limit N` is explicitly supplied. `--limit` is useful for a first smoke run, but any limited output must be described as a pilot and must not be treated as satisfying the publication sample-size gates. To use a release you have acquired and reviewed yourself, provide the source files explicitly instead of using `--fetch-registered-pilot`:

```bash
scripts/realdata_campaign.sh \
  --primevul /path/to/reviewed-primevul.jsonl \
  --secvuleval /path/to/reviewed-secvuleval.parquet \
  --cwe CWE-121 \
  --data-root "$HOME/evidencelab-data-cwe121" \
  --out-root "$HOME/evidencelab-campaign-cwe121" \
  --profile profiles/research-publication-c-cpp-joern.json
```

Use only the input combinations justified by the research protocol. Avoid merging different official partitions blindly. Preserve the source release and artifact checksum; keep raw datasets and sensitive source metadata outside the Git repository.

## Pipeline stages and outputs

The script performs the following stages, in order:

1. Checks that the installed EvidenceLab package and profile are accessible.
2. Optionally fetches registry-pinned pilot artifacts.
3. Uses EvidenceLab's existing `dataset-import-primevul` and/or `dataset-import-secvuleval` commands with a selected CWE filter.
4. Runs the pack's metadata census and optional source-hash verification, writing JSON reports rather than source contents.
5. Runs `dataset-validate` requiring known-label provenance, case identity, and source hashes.
6. Requires Joern for capture unless `--prepare-only` is selected.
7. Calls the existing `research-build` command. Its source references, capture results, split result, quality output, and build report are preserved under the campaign output directory.
8. Materializes the composed corpus into separate self-contained family directories using the patterns already checked into the repository. It copies bytes and rewrites relative paths; it doesn't change a pattern's claims or expected labels.
9. Runs `research-check` without strict-gate enforcement to collect metrics, and separately runs it with the publication profile and strict gates. The strict run may and should fail when the pilot is too small, source/label provenance is insufficient, hidden validation is unavailable, confidence intervals are too wide, or any other gate fails.

Key artifacts are stored under `OUT_ROOT/reports/`, `OUT_ROOT/corpus/`, and `OUT_ROOT/evaluation/CWE-120/families/` or `OUT_ROOT/evaluation/CWE-121/families/`.

## Interpreting results correctly

- A successful import means the data was mapped into EvidenceLab's record structure; it does not prove that labels are true.
- A successful Joern capture means the configured analyzer completed the recorded capture workflow; it does not prove a vulnerability is present or absent.
- `MATCH`, `NO_MATCH`, `UNKNOWN`, and `PARTIAL` have distinct semantics. Do not promote `UNKNOWN`/`PARTIAL` to a confident negative.
- A source-hash mismatch is an integrity problem, not a reason to silently rewrite the stored hash to match the file.
- A data split passing its structural audit does not prove there is no semantic leakage. Review repository, project, commit, pair, CVE, exact-source, normalized-source, and graph overlap evidence.
- Mutation descendants are useful sensitivity tests but are not independent real-world cases.
- The same corpus evaluated by six patterns gives six evaluations, not six independent datasets.
- A strict-gate failure is an output of the research process. Keep it and diagnose it. Do not tune profiles down merely to achieve green status.
- The publication profile expects an externally-originated sealed hidden bundle. An ordinary public pilot cannot satisfy that requirement by itself.

## What counts as completion

A pipeline run is only a completed *campaign execution* when all intended stages have outputs and any failed stages are explicitly recorded. A project-level claim of publication-grade validity requires a separate review of actual labels, the study protocol, the cohort/sampling unit, independent test provenance, leakage, adequate sample counts, appropriate cluster-aware intervals, and the configured hidden validation. This pack automates mechanical checks; it does not automatically certify label truth or scientific validity.
