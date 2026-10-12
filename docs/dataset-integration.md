# Dataset and experimental-material integration

## 1. Design goal

EvidenceLab treats datasets as experimental material. The core job is to define, execute, and evaluate Evidence. A dataset importer translates a source format into a supported manifest or material contract; it must not take over the Evidence ontology or change the intended proof semantics.

The integration boundary should answer:

- Which dataset snapshot and source artifact are being used?
- What is the stable identity of each case?
- Which source files or other artifacts belong to each case?
- What label or claim did the dataset actually declare, and who is the authority for it?
- What locations and relations are explicitly supplied?
- Which fields were inferred or transformed, and by which mapping?
- Can the imported material be checked and reproduced without changing the original source?

## 2. Integration paths

Choose the narrowest supported path that preserves the information needed by the experiment.

### Built-in importer

Use a built-in importer when the source format matches its documented expectations. Available importer commands include:

- `dataset-import-sard` for table-like SARD records in JSON, JSONL/NDJSON, CSV, or Parquet form; Parquet requires the `realdata` extra. This is **not** a universal importer for every raw SARD distribution, archive, XML file, or SARIF package.
- `dataset-import-juliet` for a Juliet C/C++ source tree. Label mode defaults to `unknown` because a file can include more than one code path or paired examples. `heuristic` label mode is exploratory and explicitly records that heuristic.
- `dataset-import-primevul` for supported PrimeVul JSONL records, with a source root for materialized source text.
- `dataset-import-secvuleval` for supported SecVulEval JSONL records.
- `dataset-import-diversevul` for supported DiverseVul JSONL records.
- `dataset-merge` to combine already materialized manifests.

An importer being present does not mean that a particular upstream release has been downloaded or independently validated. Inspect source code and metadata, choose the exact upstream snapshot, calculate hashes, and record transformations before drawing research conclusions.

### Declarative mapping

A JSON dataset model is appropriate for ordinary record sources whose fields can be reached by key paths and transformed with the supported deterministic transforms. `dataset-model-validate`, `dataset-model-preview`, and `dataset-model-import` make the mapping explicit and inspectable.

Supported record formats are JSON, JSONL/NDJSON, and CSV. The alternate `directory` input inventories files below a declared root. Supported simple transforms include `identity`, `string`, `int`, `float`, `list`, `cwe`, `truth`, and `basename`.

Example model:

```json
{
  "schema_version": "1.0",
  "dataset": {
    "id": "my-vulnerability-data",
    "name": "My Vulnerability Dataset",
    "version": "2026-10-01"
  },
  "source_root": ".",
  "input": {
    "type": "records",
    "path": "cases.jsonl",
    "format": "jsonl"
  },
  "case": {
    "id": {"path": "id", "transform": "string"},
    "truth": {
      "state": {"path": "label", "transform": "truth"},
      "authority": "DATASET_DECLARED"
    },
    "claims": [
      {"type": "weakness", "value": {"path": "cwe", "transform": "cwe"}}
    ],
    "artifacts": [
      {"id": "source", "kind": "source", "path": {"path": "source_path", "transform": "string"}}
    ],
    "locations": [
      {"artifact": "source", "line": {"path": "line", "transform": "int"}}
    ]
  }
}
```

This is an example contract; field names and paths must be adapted to the actual input records. A mapping does not imply that the dataset's semantics have been verified.

Validate, preview, and import:

```bash
python -m evidencelab dataset-model-validate \
  --model examples/dataset-model/simple-vuln-dataset.json

python -m evidencelab dataset-model-preview \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --limit 10

python -m evidencelab dataset-model-import \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --out /tmp/canonical-material.json
```

### Mapping digest semantics

The `dataset-model-validate` response includes `mapping_digest`, which is
SHA-256 over the canonical JSON representation of the parsed mapping.
Object-key order and formatting whitespace do not affect this digest.

The `dataset-model-preview` and `dataset-model-import` outputs include
`mapping_sha256`, which is SHA-256 over the raw bytes of the mapping file.
It identifies the exact file representation, so formatting changes can
change this value even when the parsed JSON is unchanged.

These two values intentionally represent different things and are not
expected to be equal. Use `mapping_digest` to identify the canonicalized
mapping content and `mapping_sha256` to identify the exact source file.

### Programmatic adapter

Use a programmatic adapter for database records, proprietary or binary formats, nested archives, complex SARD structures, or sources with semantic rules that cannot be represented by the declarative mapping. The adapter should produce the current canonical material contract and retain the original record or a stable pointer to it. Do not add source-specific fields to the Evidence matcher merely to avoid implementing the adapter boundary.

## 3. Material truth and Evidence outcomes are different

The canonical mapping can preserve dataset-side truth labels such as `BAD`, `GOOD`, `MIXED`, and `UNKNOWN`. The benchmark/evaluation layer can use evaluation expectations such as `MATCH` and `NO_MATCH`. These values belong to different concepts.

A declared positive label does not force the Evidence engine to return `MATCH`; the Evidence may not observe its required proof. A declared safe label does not prove that a particular pattern should return `NO_MATCH`; the case may be outside the pattern's scope or the analysis may be incomplete. Preserve label authority and keep computed results independently recorded.

## 4. Identity and provenance requirements

For every source snapshot, record:

- upstream project and dataset name;
- release/version/date and acquisition URL or method;
- archive or input-file digest;
- license and usage restrictions;
- case IDs and original record IDs;
- source-file paths and SHA-256 digests when material is present;
- mapping code/file and its digest;
- label source, authority, transformations, and uncertainty;
- artifact copying or normalization steps;
- exclusions and reasons for exclusions.

Avoid unstable generated IDs when a stable source record ID exists. If a derived identifier is necessary, retain the formula and original identity. Do not replace the raw source with normalized files without preserving enough information to reproduce the mapping.

## 5. Path safety

Declarative mapping paths are interpreted relative to `source_root`. Absolute artifact paths and paths that escape the declared root are rejected. A record that names a missing source artifact should remain unresolved or missing in the material report; the importer must not fabricate a replacement file.

## 6. SARIF integration

SARIF is an interchange format for static-analysis results, not automatically ground truth. Use `sarif-ingest` to convert a supported SARIF report into graph/observation form, or `sarif` to export a supported EvidenceLab report as SARIF. Preserve the tool identity, rule identifiers, result locations, fingerprints, and original SARIF artifact. A SARIF finding is an analyzer observation; its presence or absence is not a proof obligation by itself.

## 7. SARD specifically

SARD is a collection and distribution ecosystem for software assurance test cases. EvidenceLab can integrate selected SARD material, but `dataset-import-sard` should be understood as an importer for table-like records, not a full universal archive crawler for all SARD schemas and historic snapshots.

For a SARD experiment:

1. Download a specific SARD distribution or test suite from an official NIST endpoint.
2. Save the original archive and checksum it.
3. Identify the exact metadata table, source files, SARIF documents, labels, and flaw locations relevant to the experiment.
4. Implement or select a mapping/adapter for those structures.
5. Preserve original IDs, SARD suite/version, weakness identifiers, source-file hashes, test status, flaw locations, and pair relationships when they exist in the source.
6. Validate the mapping and inspect a sample of imported records by hand.
7. Record omitted fields and unresolved semantics rather than inferring them silently.
8. Audit label provenance, case identity, hashes, and split leakage before evaluation.

Official source: https://samate.nist.gov/SARD/

## 8. Build a corpus only after the mapping is stable

Use `research-build` or `capture-corpus` when source material is ready for analysis and you need auditable capture/evaluation manifests. Do not begin with a mixed, unverified corpus and assume that later metrics will reveal corrupted identity or mislabeled cases.

Recommended sequence:

```text
Acquire and hash snapshot
       -> map/import metadata
       -> validate and preview mapping
       -> verify source artifacts and case identity
       -> inspect label authority and unknown cases
       -> capture analyzer artifacts
       -> audit lineage and leakage
       -> split the material
       -> evaluate Evidence
       -> replay witnesses and freeze provenance
```

See [Real-world runbook](real-world-runbook.md), [Benchmark design](benchmark-design.md), and [Reproducibility](reproducibility.md).
