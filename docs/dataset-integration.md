# Dataset and experimental-material integration

EvidenceLab treats external datasets as material for a research task, not as the definition of Evidence. An importer or mapping must preserve what the source actually declares and must not silently convert dataset labels into matcher outcomes.

## Choose an integration path

| Input | Preferred path | Important boundary |
|---|---|---|
| Simple JSON, JSONL/NDJSON, or CSV records | Declarative dataset model | Explicit field mapping and transforms. |
| Supported table-like SARD records | `dataset-import-sard` | Not a universal reader for every SARD archive, XML schema, or SARIF package. |
| Juliet C/C++ source tree | `dataset-import-juliet` | Defaults to `unknown`; filename/path heuristic labels remain heuristic. |
| Supported PrimeVul, SecVulEval, or DiverseVul JSONL | Corresponding built-in importer | Check its exact fields and source-root requirements with `--help`. |
| Complex, nested, proprietary, or database sources | Programmatic adapter | Preserve original records or a stable link and document transforms. |
| SARIF report | `sarif-ingest` or an explicit adapter | A SARIF finding is an analyzer observation, not ground truth or a full graph. |

An importer being available does not mean EvidenceLab ships that dataset or validates every upstream snapshot. Record the exact source release, acquisition method, license, and hashes.

## Declarative mapping: validate, preview, import

Start with the bundled example and inspect each stage:

```bash
python -m evidencelab dataset-model-validate \
  --model examples/dataset-model/simple-vuln-dataset.json

python -m evidencelab dataset-model-preview \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --limit 3

python -m evidencelab dataset-model-import \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --out /tmp/canonical-material.json
```

The mapping supports record inputs in JSON, JSONL/NDJSON, and CSV, plus a directory-inventory input. Supported simple transforms are `identity`, `string`, `int`, `float`, `list`, `cwe`, `truth`, and `basename`. The model names the dataset, input/root, case identity, truth, claims, artifacts, locations, and relations. Adapt the field paths to the real source; a valid mapping does not prove the source labels are semantically correct.

## Truth labels and matcher outcomes are different

Material can preserve `BAD`, `GOOD`, `MIXED`, or `UNKNOWN` as dataset-declared truth. Evidence execution reports `MATCH`, `NO_MATCH`, `PARTIAL`, or `UNKNOWN`. These are different concepts: `BAD` does not force `MATCH`, and a `GOOD` label does not prove that a particular Evidence should return `NO_MATCH`. Keep label authority and computed outcomes separately recorded.

## Paths and digests

Artifact paths are resolved relative to `source_root`. Absolute artifact paths and paths escaping that root are rejected. Missing artifacts should remain missing/unresolved; do not fabricate replacements to make import pass.

The model validator's `mapping_digest` is SHA-256 of the canonical JSON representation after parsing. The preview/import `mapping_sha256` is SHA-256 of the mapping file's exact bytes. They identify different things and are not expected to match: formatting-only changes can alter the file hash while leaving the canonical digest unchanged.

## Preserve identity and provenance

For each snapshot or case, retain what is available and relevant:

- upstream dataset/repository, version or commit, acquisition URL/method, date, license, and archive digest;
- stable case ID and original record ID;
- source paths and SHA-256 hashes;
- label value, authority, and any heuristic or transformation;
- mapping/adapter identity and digest;
- line/function/flaw locations, pairs/relations, exclusions, and unresolved fields.

Use `dataset-validate` for manifest checks. Enable `--require-label-provenance`, `--require-case-identity`, and `--require-source-hash` when those properties are required for the experiment. Investigate failed checks rather than weakening them just to obtain `PASS`.

## Built-in importer examples

For a supported table-like SARD export:

```bash
python -m evidencelab dataset-import-sard \
  --input sard-records.jsonl \
  --source-root ./sard-snapshot \
  --out /tmp/sard-manifest.json
```

For a Juliet C/C++ source tree, keep labels conservative unless there is another documented authority:

```bash
python -m evidencelab dataset-import-juliet \
  --root ./juliet-c-cpp \
  --cwe CWE-121 \
  --label-mode unknown \
  --out /tmp/juliet-manifest.json
```

Use `--label-mode heuristic` only when you intend to test filename/path-derived labels and will report them as heuristics. For PrimeVul, SecVulEval, and DiverseVul, confirm required input and source-root arguments with each command's `--help`.

## SARD-specific caution

For SARD, choose one suite/snapshot first; inspect its tables, source tree, reports, labels, and flaw-location fields. Map only fields whose meaning you can justify, preserve original IDs and pair relationships when available, and manually inspect a sample of imported cases. See the [NIST SARD site](https://samate.nist.gov/SARD/) for upstream material.

## Recommended order

```text
Acquire and hash a source snapshot
  -> inspect records and licenses
  -> validate and preview the mapping
  -> verify IDs, labels, and source artifacts
  -> import canonical material
  -> capture analyzer artifacts
  -> audit lineage/leakage and split cases
  -> evaluate, replay witnesses, and freeze provenance
```

See [Research methodology](research-methodology.md), [Benchmark design](benchmark-design.md), and [Reproducibility](reproducibility.md) before making an external performance claim.
