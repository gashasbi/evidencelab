# Standards and ecosystem matrix

| Source or tool | Role | EvidenceLab relationship | Important limitation |
|---|---|---|---|
| NIST SAMATE / SARD | Software assurance test material and associated metadata | External material that can be imported or mapped for a research task | Distributions and metadata forms vary; a supported table importer is not a universal SARD archive reader. |
| Juliet | Structured weakness test suites | Built-in C/C++ source-tree importer | Filename-derived labels are heuristic and the default import preserves unknown labels. |
| SARIF | Static-analysis result interchange | Ingest supported result reports or export EvidenceLab reports | A SARIF result is an analyzer observation, not authoritative ground truth or a full program graph. |
| CWE | Weakness taxonomy | Scope, classification, and source reference for Evidence families | A CWE ID does not define executable proof semantics by itself. |
| Joern / CPG | Graph construction and source analysis | Supported external analyzer and capture workflow | Joern release, configuration, and analysis completeness must be recorded; a CPG may omit facts needed for a claim. |
| CodeQL | Query-based semantic analysis | Related ecosystem and potential observation provider through explicit integration work | EvidenceLab does not embed CodeQL or claim that arbitrary CodeQL output is automatically converted. |
| Semgrep | Rule-driven static analysis | Related rule-testing ecosystem and potential finding source | EvidenceLab does not replace Semgrep's rule engine or treat its findings as proof automatically. |
| W3C PROV | Provenance model | Conceptual basis for traceable entities, activities, and derivations | Hashes and provenance records support auditability but do not guarantee semantic truth. |
| JSON Schema | Machine-readable structure validation | Used for the public artifact contract | Schema validity does not prove sound Evidence semantics or research-grade experimental design. |

## Design principle

External tools and standards inform the platform boundary; they do not define the Evidence object. EvidenceLab's core responsibility is to make researcher-authored Evidence executable and auditable while preserving distinctions among input labels, observations, derivations, witnesses, counter-evidence, uncertainty, and evaluation.
