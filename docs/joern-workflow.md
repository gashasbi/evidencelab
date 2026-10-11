# Joern workflow reference

This page is a concise operational companion to [Joern integration](joern-integration.md). Use that full guide for the upstream installation links and explanation of capture semantics.

## Capture pipeline

```text
Source file or source path
        |
        v
joern-parse --------------------> cpg.bin
        |
        +--> joern-export --format=graphml --> graphml/export.xml
        |
        +--> joern-export --format=graphson -> graphson export
        |
        +--> joern-slice data-flow ----------> dataflow.json (optional)
        |
        v
capture-manifest.json
        |
        v
EvidenceLab graph parser and semantic enrichment
        |
        v
Canonical graph -> Evidence matcher -> witness replay -> report
```

## Preflight

```bash
command -v joern-parse
command -v joern-export
command -v joern-slice
python -m evidencelab doctor --joern
```

## One-file capture

```bash
python -m evidencelab capture \
  --source path/to/example.c \
  --out /tmp/example-capture \
  --dataflow-timeout 240 \
  --dataflow-slice-depth 8
```

## Run the full capture/merge test

```bash
./scripts/joern_e2e.sh /tmp/evidencelab-joern-e2e
```

Review `/tmp/evidencelab-joern-e2e/e2e-report.json` and the per-case `e2e.log` files. `PASS_WITH_WARNINGS` means the main artifacts were generated but data-flow capture may have been degraded; it is not equivalent to a fully complete analysis.

## Data-flow semantics and bounds

Joern documents `reachableBy` and `reachableByFlows` as data-flow query steps, while `joern-slice data-flow` creates an exportable slice. The slicer and CPG query language are upstream Joern features; EvidenceLab records the resulting artifacts and does not replace those queries.

References:

- https://docs.joern.io/cpgql/data-flow-steps/
- https://docs.joern.io/cpg-slicing/
- https://docs.joern.io/dataflow-semantics/
- https://docs.joern.io/export/
