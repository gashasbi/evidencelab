# EvidenceLab documentation

This documentation describes the EvidenceLab 1.0.0 public release. Package version `1.0.0` and artifact schema version `1.0` are separate identifiers. Examples in this repository are reference material and must not be mistaken for an independent publication-grade benchmark.

## Recommended reading order

1. [Installation](installation.md): Python environment, runtime/development extras, and verification.
2. [Quickstart](quickstart.md): run the shipped ELS and experimental-material examples.
3. [Architecture](architecture.md): system boundaries, canonicalization, and execution flow.
4. [Joern integration](joern-integration.md): install and validate the external analyzer; capture source into graph artifacts.
5. [ELS reference](evidence-dsl.md): syntax and semantics for researcher-authored Evidence.
6. [Evidence model](evidence-model.md): observations, derivations, proof states, witnesses, and counter-evidence.
7. [Dataset integration](dataset-integration.md): mapping and importer contracts for external material.
8. [Research methodology](research-methodology.md): experiment design, validation, splits, leakage, and evaluation.
9. [CLI reference](cli-reference.md): command groups, examples, and options.
10. [Troubleshooting](troubleshooting.md): common installation, capture, schema, and evaluation failures.

## Reference pages

| Page | Use it for |
|---|---|
| [Evidence standard](evidence-standard.md) | Required Evidence Pattern semantics and review rules. |
| [Evidence taxonomy](evidence-taxonomy.md) | Evidence dimensions and classes. |
| [Benchmark design](benchmark-design.md) | Case classes, mutations, leakage controls, metrics, and hidden evaluation. |
| [Real-world runbook](real-world-runbook.md) | Handling SARD, Juliet, and external corpora reproducibly. |
| [Researcher playbook](researcher-playbook.md) | A concise end-to-end research workflow. |
| [Researcher protocol](researcher-protocol.md) | Investigation discipline, evidence decisions, and freeze criteria. |
| [Research basis](research-basis.md) | Design relationships to SARD, SARIF, CWE, provenance, CodeQL, and graph analysis. |
| [Standards matrix](standards-matrix.md) | Which external standards and tools define inputs or provide references. |
| [External references](external-references.md) | Primary-source links. |
| [External-scale evaluation](external-scale.md) | Conditions for defensible external-scale claims. |
| [Joern adapter contract](joern-adapter-contract.md) | What the adapter captures and how raw analyzer facts map to canonical observations. |
| [Joern workflow](joern-workflow.md) | Operational capture and end-to-end test procedures. |
| [Performance](performance.md) | Repeated measurements and interpretation. |
| [Reproducibility](reproducibility.md) | Immutable identities, hashes, ledgers, and replay. |
| [Security model](security-model.md) | Input boundaries, execution risks, and trust assumptions. |
| [Submission format](submission-format.md) | Packaging a research submission for validation. |
| [Task specification](task-specification.md) | How to define a research task. |
| [Witness validation](witness-validation.md) | Independent witness replay and benchmark validation. |
| [Troubleshooting](troubleshooting.md) | Diagnosis and safe recovery from common errors. |

## Documentation conventions

- Commands are shown from the repository root unless stated otherwise.
- Python commands should run inside the virtual environment created for this checkout.
- Examples write disposable outputs under `/tmp` unless an output path is explicitly named.
- A command reporting `PASS` means that command's checks passed; it does not establish a broader scientific claim.
- If the analysis is incomplete, preserve the reported degraded/unknown state. Do not turn a timeout or missing artifact into a negative vulnerability result.
- Treat external tool requirements as separate from Python package requirements. In particular, Joern is an independently installed analyzer.
