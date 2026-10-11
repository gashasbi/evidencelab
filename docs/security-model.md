# Security and integrity model

## Purpose

EvidenceLab evaluates Evidence definitions and transforms research artifacts. It is not a sandbox for executing hostile code, and it does not guarantee that an external analyzer is safe to run against arbitrary input. Security depends on the environment in which source files, analyzers, downloads, and generated executables are processed.

## Input boundaries

Treat all of the following as untrusted until validated:

- source repositories and archives;
- JSON, JSONL, CSV, XML/GraphML, GraphSON, SARIF, TEF, and other imported artifacts;
- researcher-defined dataset mappings and benchmark manifests;
- graph node/edge properties and metadata;
- external URLs and dataset registry entries;
- hidden evaluation bundles and third-party reports.

The graph parser rejects GraphML containing DTD/entity declarations. Declarative dataset mapping prevents absolute artifact paths and path escapes beyond the declared source root. These controls reduce particular attack surfaces; they do not make arbitrary input safe in every context.

## Analyzer isolation

Joern and other analyzer processes may parse large or malformed source projects and can consume substantial CPU, memory, disk, and time. Run them in a container, VM, or dedicated account with:

- CPU and memory limits;
- process and wall-clock timeouts;
- a bounded writable output directory;
- read-only source mounts where possible;
- network disabled unless a documented analysis step needs it;
- no production credentials, SSH keys, cloud tokens, or unrelated private files;
- a cleanup strategy for temporary graphs and generated binaries.

Do not run untrusted source or build scripts with elevated privileges merely to make analysis succeed.

## Integrity versus semantic trust

A SHA-256 digest detects byte changes relative to a known digest. A manifest records the identity and lineage asserted at capture time. Neither proves that the original data was correct, that a label was authoritative, that a source URL was truthful, or that an analyzer's semantics were complete.

Likewise:

- an authentic dataset label is not an Evidence match;
- a valid JSON Schema instance is not necessarily a valid research design;
- a successful Joern process is not proof that the CPG has every relation a pattern needs;
- a hidden bundle with a valid seal is not proof of independent evaluator custody;
- witness replay is not a complete benchmark evaluation.

## Secrets and hidden benchmarks

Do not commit HMAC keys, credentials, restricted datasets, proprietary code, or evaluator-only cases. If hidden-benchmark verification uses a secret key supplied through an environment variable, never write the key into a command log, manifest, or public report. Verify what the bundle contains before distributing it.

## Failure reporting

Keep infrastructure errors separate from vulnerability labels. Missing executables, timeouts, invalid exports, failed parsing, unresolved external calls, and partial slices must remain explicit statuses. Do not convert a failed analysis into `NO_MATCH` or a safe label.

## Responsible handling

Use only source material that you are authorized to analyze and retain. Respect dataset licenses, privacy obligations, and disclosure policies. When a result indicates a potentially real vulnerability, follow the affected project's responsible disclosure process.

See also the repository-level [Joern integration](joern-integration.md), and [Reproducibility](reproducibility.md).
