# Research basis and engineering boundaries

EvidenceLab draws on public security taxonomies, benchmark ecosystems, interchange formats, provenance principles, and graph-oriented program-analysis tools. These sources inform the design; they do not replace the researcher's responsibility to define and test Evidence semantics.

## NIST SAMATE and SARD

SARD provides software assurance test cases and associated metadata. It is a source of experimental material, not the EvidenceLab ontology. Individual SARD releases may contain distinct metadata schemas, source trees, reports, tool outputs, paired cases, and labels. Record the exact suite/snapshot and select an adapter appropriate to the format instead of assuming that every SARD archive can be imported by one command.

Official source: https://samate.nist.gov/SARD/

## Juliet

Juliet provides structured test suites for weakness testing, including C/C++ cases that can contain bad and good paths or paired files. Filename-based heuristics are not authoritative semantic truth. The built-in importer preserves unknown labels by default and makes heuristic mode explicit.

Official source: https://samate.nist.gov/SARD/test-suites/112

## SARIF

SARIF is the OASIS Static Analysis Results Interchange Format. It standardizes how static-analysis tools report results; it does not establish the correctness of an individual finding or supply all program semantics required by an Evidence definition.

Official source: https://sarifweb.azurewebsites.net/

## CWE

MITRE CWE provides a taxonomy of software weakness types. A CWE identifier helps define a research scope but is not an executable proof rule and does not settle which source constructs are sufficient evidence for a particular instance.

Official source: https://cwe.mitre.org/

## Provenance

W3C PROV provides a conceptual model for describing entities, activities, and agents in data derivation. EvidenceLab uses provenance as an engineering discipline: input artifacts and observations should be identifiable, derivations should name their inputs and methods, and results should carry enough identity to reproduce or audit them. A hash or manifest alone is not a guarantee of truth.

Official source: https://www.w3.org/TR/prov-overview/

## Joern and Code Property Graphs

Joern constructs Code Property Graphs and offers graph queries and data-flow analysis. EvidenceLab can consume Joern exports while keeping Evidence definitions at a canonical semantic boundary. The projects have different roles: Joern provides analyzer observations; EvidenceLab defines and evaluates researcher-authored Evidence over supported graph inputs.

Official sources: https://joern.io/ and https://docs.joern.io/

## CodeQL, Semgrep, and graph-oriented rule systems

CodeQL, Semgrep, and other static-analysis ecosystems demonstrate useful practices for expressing queries, testing rules, and reviewing findings. EvidenceLab does not require that every analyzer export be translated into one query syntax. Its purpose is to make Evidence proof obligations, witnesses, counter-evidence, uncertainty, and research evaluation explicit across selected observation providers.

Official sources:

- https://codeql.github.com/docs/
- https://semgrep.dev/docs/

## EvidenceLab's engineering contribution

The central separation is:

```text
External material and analyzer outputs
                 |
                 v
Explicit adapters and canonical contracts
                 |
                 v
Researcher-authored executable Evidence
                 |
                 v
Coherent witnesses, counter-evidence, uncertainty
                 |
                 v
Evaluation, provenance, replay, and reproducible reports
```

The value proposition is not that a new framework knows every dataset or analyzer. It is that Evidence definitions and their tests can be made inspectable, executable, falsifiable, and auditable while source-specific acquisition and observation remain explicit.

## Non-goals

EvidenceLab does not claim to auto-generate scientifically valid Evidence, replace source analyzers, guarantee complete call graphs, determine dataset labels independently, or certify publication-grade generalization from bundled demonstration cases.
