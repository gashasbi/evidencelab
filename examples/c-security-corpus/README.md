# EvidenceLab C Security Test Corpus

- Version: 1.0.0
- Samples: 69
- CWE-labelled families: 23
- Labels: VULN, SAFE, UNKNOWN

## Directory structure

- `samples/<family>/vuln/`: intended vulnerable patterns
- `samples/<family>/safe/`: local mitigation controls
- `samples/<family>/unknown/`: missing contracts or context
- `metadata/manifest.json`: full machine-readable manifest
- `metadata/manifest.csv`: spreadsheet-friendly manifest
- `metadata/families.json`: family summaries
- `metadata/cwe121_pilot.json`: initial CWE-121 subset
- `metadata/SHA256SUMS`: hashes of generated files
- `tools/validate_corpus.py`: validates paths, labels, IDs, and hashes

## Important limitations

These are synthetic test fixtures, not production software or exploit payloads.
VULN indicates the intended weakness in the snippet, not guaranteed exploitability.
SAFE indicates a local mitigation only, not whole-program safety.
UNKNOWN indicates that necessary context, ownership, extents, or external contracts
are absent. CWE mappings are organizational labels and should be reviewed.

Not every CWE family is necessarily supported by the current EvidenceLab matcher.
Parser acceptance does not imply vulnerability detection.

## Suggested test order

1. Run the corpus validator.
2. Start with `metadata/cwe121_pilot.json` and the existing CWE-121 workflow.
3. Compare vulnerable samples with SAFE controls.
4. Check that UNKNOWN cases do not become definitive safe results merely because
   relevant evidence is missing.
5. Use other families for ingestion and parser smoke tests unless matching rules
   and expected evidence are explicitly in scope.

The C files are source fixtures and are not intended to be compiled or executed as
a single application. Use static analysis and an isolated environment.
