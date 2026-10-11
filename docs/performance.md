# Performance evaluation

## Purpose

Performance measurements help establish whether an Evidence definition and analysis workflow can operate within an explicit resource budget. Performance is separate from semantic correctness: a fast result can be wrong, and a timeout is not evidence that a vulnerability is absent.

## What to record

Capture:

- hardware, operating system, Python, EvidenceLab, and analyzer versions;
- source or benchmark digest, case count, and graph size;
- analyzer parse/export time and data-flow settings;
- candidate count and any candidate/path/combination caps;
- wall-clock time by stage;
- memory and disk use where practical;
- timeout, parse-failure, and export-failure counts;
- repeated-run configuration and whether caches or warm state were used;
- per-case outcomes and analysis completeness.

## Repeat benchmark measurements

The `performance` command evaluates a benchmark/pattern pair repeatedly and prints measurement results. Confirm available output options with `python -m evidencelab performance --help` for the installed release:

```bash
python -m evidencelab performance \
  --benchmark path/to/benchmark.json \
  --pattern path/to/pattern.json \
  --repeats 5 > /tmp/performance-output.json
```

Treat redirected output as machine-readable JSON only if the command's output format is JSON for the exact release; otherwise save it as a text log and use the generated artifacts documented by the command. Keep the benchmark and Pattern digests with the measurement.

## Joern budgets

Joern capture has separate operations: parsing, graph export, optional GraphSON export, and data-flow slicing. `--dataflow-timeout` bounds the slice operation; `--dataflow-slice-depth` and filters restrict the slice. Record these separately because total wall time is not a pure matcher measurement.

## Interpretation

Report repeated-run distributions or summary statistics rather than a single favorable observation. Separate analyzer startup, source-dependent costs, graph size, matching time, replay time, and I/O. Do not hide timeouts by removing failed cases from the denominator. Report the trade-off between analysis bounds and completeness when a smaller depth or narrower filter changes results.
