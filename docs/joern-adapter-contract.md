# Joern adapter contract

## Purpose

The adapter boundary converts Joern artifacts into EvidenceLab graph inputs while retaining enough metadata to audit how the inputs were produced. Joern remains an independent analyzer with its own release cycle and semantics.

## Supported input artifacts

The graph parser supports these Joern-related inputs:

- GraphML exported from a CPG;
- GraphSON exported from a CPG;
- Joern `DataFlowSlice` JSON;
- explicit reachable-by-flow path JSON where its supported shape matches the parser contract;
- an EvidenceLab canonical graph JSON produced by a prior normalization or merge operation.

For analyzer completeness, prefer retaining the full CPG and the original exports. GraphML can lose list-valued properties; keep GraphSON and `cpg.bin` when those details matter. A data-flow slice is a partial view, not a full CPG.

## Capture contract

`evidencelab capture` invokes:

1. `joern-parse <source> --output <out>/cpg.bin`;
2. `joern-export <cpg> --repr=all --format=graphml --out <out>/graphml`;
3. optionally, `joern-export <cpg> --repr=all --format=graphson --out <out>/graphson`;
4. optionally, `joern-slice data-flow` with slice depth and filters.

The current default requests GraphSON and data-flow slicing. A data-flow timeout or command failure is fatal unless `--best-effort-dataflow` is enabled. In best-effort mode, the capture manifest reports degraded status and must not be treated as evidence of complete analysis.

## Required provenance

A capture manifest records, where available:

- source path and SHA-256;
- EvidenceLab package and artifact-contract versions;
- Joern version;
- artifact paths;
- command stdout/stderr;
- data-flow configuration and status;
- analysis attestation level and capture status.

Preserve the manifest next to the unmodified source artifacts. If source or exports are moved, copied, or transformed, generate the corresponding derived artifact record and hashes.

## Normalization rules

The canonical graph boundary exposes stable EvidenceLab node/edge types and selected semantic relations. Raw edge labels and properties should remain inspectable. For example, a Joern relation can support a canonical `DATA_FLOW` relation only when the adapter's mapping and artifact content justify that interpretation. Similar labels do not by themselves prove semantic equivalence.

If the input is incomplete, a required node or relation is missing, an export is lossy, or the candidate set was bounded, preserve a completeness indicator where available and let the Evidence definition return `UNKNOWN`/`PARTIAL` when its proof obligations cannot be established.

## Failure taxonomy

Do not conflate these outcomes:

- tool not installed or not on `PATH`;
- source parsing or CPG generation failed;
- graph export failed or produced no file;
- data-flow slicing timed out;
- data-flow slicing failed without timeout;
- export parsed but was semantically incomplete;
- graph was valid but the Evidence did not match;
- a stored witness failed independent replay.

Only the latter two concern Evidence behavior. The preceding cases are capture, infrastructure, or analysis-completeness results and must be reported separately.
