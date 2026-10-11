# EvidenceLab 1.0.0 architecture

## Product boundary

EvidenceLab is an evidence-definition, evidence-execution, and research-evaluation framework. Its defining object is a researcher-authored Evidence specification. Datasets, benchmarks, source repositories, analyzer exports, and SARIF files are external material used to test or contextualize that specification.

The project does not require one corpus or one analyzer to define the central model. A SARD adapter, a Juliet importer, or a Joern capture path may translate source-specific data into a supported contract, but none of them owns the semantics of Evidence.

## High-level architecture

![evidencelab-architecture](../images/architecture.jpg)

## Principal components

### Researcher-facing definition layer

ELS is a small declarative language for concepts, slots, claims, witness requirements, counter-evidence, and policies. The parser and validator reject unsupported or invalid definitions rather than silently treating unknown constructs as meaningful. Compilation creates the current Evidence Pattern representation used by the execution engine.

### Analyzer and graph-input boundary

`evidencelab.parsers` accepts supported graph inputs such as GraphML, GraphSON, Joern data-flow slice JSON, and EvidenceLab canonical graph JSON. `evidencelab.semantics` performs deterministic semantic enrichment. The parser keeps graph metadata and raw properties where possible so a canonical relation remains traceable to the input artifact.

The Joern capture layer is external-tool orchestration, not an implementation of Joern. It invokes `joern-parse`, `joern-export`, and optionally `joern-slice`, then writes artifacts and a capture manifest. See [Joern integration](joern-integration.md).

### Experimental-material boundary

External records are integrated through built-in importers, a declarative dataset-model mapping, or a programmatic adapter. The resulting manifest captures case identity, label authority, artifact paths, locations, and provenance fields. Mapping is not Evidence; labels do not force matcher outcomes.

### Matching and proof boundary

The matcher searches for coherent assignments of graph entities to Evidence slots. Required claims are evaluated within a witness binding. Counter-evidence is bound to the same relevant witness. Missing graph facts, truncated candidate sets, unresolved numeric ranges, or degraded analyzer output may prevent a definitive decision.

### Research and evaluation boundary

Research modules manage tasks, Evidence families, experiment records, observations, derivations, provenance indexes, benchmark construction, partitioning, leakage and lineage audits, evaluation reports, witness replay, hidden-benchmark packaging, and readiness gates. Passing an individual pattern audit is different from passing research gates or validating an external generalization claim.

## Core data distinctions

EvidenceLab deliberately distinguishes:

```text
External label or claim
    != raw analyzer observation
    != derived fact
    != Evidence proof obligation
    != coherent witness
    != evaluation outcome
```

For example, a SARD or Juliet case can declare that a sample is associated with a weakness. Joern can emit graph relations for the sample. EvidenceLab can derive an object-size fact from typed properties. An Evidence specification can then require proof that an observed write extent exceeds that object's proven capacity. Each step requires its own traceability; the dataset label cannot substitute for the proof.

## Outcome model

The evaluator uses `MATCH`, `NO_MATCH`, `PARTIAL`, and `UNKNOWN`. Claim-level proof states include `PROVEN`, `DISPROVEN`, `PARTIAL`, `UNKNOWN`, and `NOT_APPLICABLE`.

- `MATCH` requires a coherent witness satisfying required obligations under the relevant policies.
- `NO_MATCH` means the definition is not satisfied given a complete and trustworthy enough input for that decision.
- `PARTIAL` reports a permitted but incomplete result; it is not a synonym for success.
- `UNKNOWN` preserves insufficient information, incomplete analysis, or unresolved proof obligations.

Exact semantics are documented in [Evidence model](evidence-model.md).

## Artifact contracts

The installed package version is `1.0.0`; machine-readable artifacts use schema version `1.0`. These are intentionally independent. The public runtime accepts the current schema contract and provides an explicit migration command for imported Evidence Pattern artifacts. Migration is normalization, not semantic certification; migrated patterns require researcher review.

JSON Schema documents are in `schemas/`. Examples demonstrate the public contract in `examples/`. Keep the source ELS, compiled Pattern, graph artifacts, capture manifest, source hashes, evaluator output, and research notes together when reproducibility matters.

## Trust boundaries and failure modes

Input artifacts, mappings, external downloads, source code, and analyzer output must not be assumed trustworthy. A syntactically valid graph can still be semantically incomplete. A successful Joern process may still omit a relation needed by an Evidence definition. Timeouts, parser problems, missing executables, invalid manifests, and matcher non-matches must remain distinguishable in reports.

EvidenceLab is not a sandbox for hostile code. Isolate source analyzers using operating-system or container controls, resource limits, restricted mounts, timeouts, and network policy. See [Security model](security-model.md).

## Extension model

New source formats should be implemented as an importer or mapping into the relevant canonical material contract. New analyzers should preserve raw artifacts and declare which canonical observations and relations they can support. New Evidence definitions should be expressed as reusable patterns and validated against positive, negative, unknown, and counter-evidence cases. Extensions should not redefine the central Evidence model around a single dataset or analyzer.
