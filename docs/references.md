# Ecosystem and source references

These tools, datasets, and standards inform EvidenceLab's boundaries; their existence does not mean EvidenceLab implements every capability or fully imports every format/version. Record access dates and exact versions in a research report because upstream material changes independently.

| Source | How it relates | Limitation to keep in mind |
|---|---|---|
| [Joern](https://joern.io/) and [its documentation](https://docs.joern.io/) | External CPG construction, graph export, and data-flow analysis. | EvidenceLab invokes selected CLI tools; Joern output may be incomplete for a claim. |
| [NIST SAMATE/SARD](https://samate.nist.gov/SARD/) | Source of software-assurance test material and metadata. | Input formats vary; the built-in table importer is not a universal archive crawler. |
| [Juliet test suites](https://samate.nist.gov/SARD/test-suites/112) | Structured weakness test material. | Filename heuristics are not authoritative ground truth; the importer defaults to unknown labels. |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness taxonomy and scope reference. | A CWE identifier does not define executable proof semantics. |
| [SARIF](https://sarifweb.azurewebsites.net/) | Static-analysis result interchange. | A finding is an observation, not a complete program graph or authoritative ground truth. |
| [W3C PROV](https://www.w3.org/TR/prov-overview/) | Concepts for traceable entities, activities, agents, and derivations. | A provenance record or hash does not guarantee truth. |
| [JSON Schema](https://json-schema.org/) | Structure validation for EvidenceLab artifact contracts. | Schema validity does not establish semantic soundness or research quality. |
| [CodeQL](https://codeql.github.com/docs/) and [Semgrep](https://semgrep.dev/docs/) | Related program-analysis and rule-testing ecosystems. | EvidenceLab does not replace them or automatically adapt arbitrary output into Evidence semantics. |

The engineering boundary is: analyzers produce observations; importers/adapters preserve source identity and translate supported artifacts; the researcher defines Evidence; EvidenceLab evaluates claims and witnesses; the research workflow tests and reports validity. Do not imply integration or dataset coverage beyond the paths implemented in the checked-out version.
