# Real-world validation runbook

This runbook describes how to bring external corpora into an EvidenceLab experiment without confusing upstream labels, analyzer observations, and Evidence results. SARD, Juliet, PrimeVul, SecVulEval, DiverseVul, internal code, and CVE-derived pairs have different structures and label conventions; no generic importer can safely erase those differences.

## 1. Acquire an immutable snapshot

Choose an exact release, suite, repository commit, or archived source snapshot. Save the download URL and date, release/version, license, byte size, and SHA-256. If the source is available only from a moving branch, record the commit and create an archive for the experiment.

```bash
sha256sum downloaded-archive.zip
python -m evidencelab dataset-registry
```

Use `dataset-fetch` only for artifacts declared in the configured registry. For an artifact outside the registry, use `fetch` with an explicit URL and expected digest when available. Review licenses and access restrictions before redistribution.

## 2. Inspect the source shape

Determine whether the source is a table of case records, a source tree, a SARIF report, an archive of nested metadata and files, or a proprietary format. Read the exact importer contract and inspect representative records before importing the full source.

`dataset-import-sard` reads table-like SARD records from JSON, JSONL/NDJSON, CSV, or Parquet; it does not automatically discover every file, schema, pair, flaw location, status, and SARIF document in every raw SARD release. Implement a source-specific adapter where the upstream structure requires it.

## 3. Import with a conservative label policy

For a table-like SARD input:

```bash
python -m evidencelab dataset-import-sard \
  --input sard-records.jsonl \
  --source-root ./sard-snapshot \
  --out /tmp/sard-manifest.json
```

For Juliet source material:

```bash
python -m evidencelab dataset-import-juliet \
  --root ./juliet-c-cpp \
  --cwe CWE-121 \
  --label-mode unknown \
  --out /tmp/juliet-manifest.json
```

Juliet files can contain paired examples or multiple code paths. The default label mode is `unknown`; filename/path `heuristic` mode is exploratory and must be reported as heuristic. It is not authoritative ground truth by itself.

For JSONL records matching the implemented formats, use `dataset-import-primevul`, `dataset-import-secvuleval`, or `dataset-import-diversevul`. Confirm the exact field and source-root requirements with each command's `--help`.

## 4. Preserve identity and source semantics

Inspect and validate original case IDs, source paths and hashes, dataset release/license, label value and authority, CWE values, line/function/flaw locations, pair relationships, and all importer transformations or exclusions. A guessed label or inferred location is a research annotation and must be described as such.

For declarative mappings, validate and preview before materialization:

```bash
python -m evidencelab dataset-model-validate --model mappings/source-model.json
python -m evidencelab dataset-model-preview --model mappings/source-model.json --limit 20
python -m evidencelab dataset-model-import --model mappings/source-model.json --out /tmp/material.json
```

## 5. Validate provenance

```bash
python -m evidencelab dataset-validate \
  --input /tmp/sard-manifest.json \
  --require-label-provenance \
  --require-case-identity
```

Use `--require-source-hash` when the manifest is expected to contain source hashes for every relevant case. Investigate failures rather than weakening the checks solely to obtain a passing status.

## 6. Capture source and retain raw artifacts

After the material mapping is stable, capture selected cases with the intended analyzer. For Joern, follow [Joern integration](joern-integration.md). Preserve the source, raw export, capture manifest, exact command, analyzer version, and hash. Keep capture failures separate from pattern non-matches.

## 7. Audit leakage and split

Choose repository, project, CVE, mutation, or chronological grouping according to the claim. Keep descendants of the same source together. Run the appropriate leakage, lineage, and split audits before tuning or interpreting held-out scores.

## 8. Evaluate and replay witnesses

Use the profile appropriate to the intended research claim. Persist per-case outcomes and witness artifacts, then independently replay stored witnesses where supported. Report unknown and infrastructure-error counts, not just the aggregate metrics.

## 9. Hidden validation and external claims

A hidden set is meaningful only if an independent evaluator controls selection, custody, and access during development. Sealing can help detect tampering but cannot prove who had access to the data.

## 10. Publish limitations

State exact source snapshots, inclusion/exclusion rules, label authority, mapping code, analyzer versions, analysis completeness, split identity, leakage controls, replay results, and known limitations. If imported metadata lacks SARD flaw locations or pair relationships, say so explicitly instead of implying complete SARD semantic coverage.
