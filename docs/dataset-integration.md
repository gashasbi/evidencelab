# Dataset and experimental-material integration

EvidenceLab treats datasets as experimental material, not as the definition of Evidence. Importers and mappings should preserve what the source declares without silently converting dataset labels into matcher outcomes.

## Choose an integration path

| Input | Typical path | Boundary to remember |
|---|---|---|
| Simple JSON, JSONL/NDJSON, or CSV | Declarative dataset model | Mapping fields and transforms must be explicit. |
| Supported table-like SARD material | `dataset-import-sard` | Not a universal importer for every SARD archive or format. |
| Juliet C/C++ source tree | `dataset-import-juliet` | Heuristic labels remain heuristic; inspect importer options. |
| Supported PrimeVul, SecVulEval, or DiverseVul JSONL | Corresponding importer | Check required fields and source-root behavior with `--help`. |
| SARIF | `sarif-ingest` or a custom adapter | A finding is an analyzer observation, not ground truth or a full graph. |
| Complex or proprietary data | Programmatic adapter | Preserve original records or a stable source reference and document transforms. |

An importer being present does not mean EvidenceLab distributes that dataset or validates every upstream snapshot. Record the exact release/commit, acquisition method, license, source hashes, case IDs, and label authority.

## Declarative mapping workflow

Start with the bundled example:

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

The model specifies dataset identity, record input, case identity, truth, claims, artifacts, locations, and relations. Supported simple transforms include `identity`, `string`, `int`, `float`, `list`, `cwe`, `truth`, and `basename`; confirm the accepted schema and behavior from the model schema and command help in your checkout.

Validate and preview representative records before importing a full dataset. Inspect generated case IDs, paths, labels, and relations. A successful mapping validates the mapping contract, not the truth of source labels.

## Labels and outcomes are different

Dataset material may carry labels such as `BAD`, `GOOD`, `MIXED`, or `UNKNOWN`. Evidence execution can return `MATCH`, `NO_MATCH`, `PARTIAL`, or `UNKNOWN`. These are different dimensions:

- a `BAD` label does not force `MATCH`;
- a `GOOD` label does not prove that all relevant evidence is absent;
- unknown or disputed labels should not be silently converted into definitive truth;
- a parser/importer warning or incomplete source capture must remain visible.

Keep raw records, transformation rules, mapping digest, source hashes, exclusions, and import logs.

## Paths and integrity

Resolve artifact paths relative to the declared source root. Do not weaken path restrictions to accommodate absolute paths or paths that escape that root. Distinguish a canonical mapping digest from a hash of the original mapping file bytes: they may identify different representations.

A digest can detect byte changes relative to a known value; it does not establish semantic correctness, upstream label validity, or independent origin.

See [Research methodology](research-methodology.md) for benchmark design and [Reproducibility](reproducibility.md) for provenance records.
