# Architecture

EvidenceLab separates **what an analyzer observed**, **what the researcher claims**, and **what the evidence supports**. Its central artifact is the researcher-authored Evidence definition; datasets and analyzers are inputs, not the authority on Evidence semantics.

![EvidenceLab architecture](../images/architecture.jpg)

## Execution path

```text
External source / dataset
        |
        +--> Analyzer or importer --> raw artifacts + provenance
                                      |
ELS definition --> validate --> compile |
                                      v
                         canonical graph / material contract
                                      |
                                      v
                     candidate bindings and claim evaluation
                                      |
                                      v
                  witness + counter-evidence + completeness
                                      |
                                      v
                          report / evaluation artifacts
```

## Main boundaries

- **ELS definition layer:** parses and validates researcher-authored concepts, slots, claims, witnesses, counter-evidence, and execution policies.
- **Analyzer boundary:** parsers accept supported graph inputs, including EvidenceLab canonical graph JSON and selected GraphML, GraphSON, and Joern slice forms. The Joern adapter orchestrates external tools; it does not implement Joern.
- **Experimental-material boundary:** built-in importers, declarative mappings, or programmatic adapters translate external records into a supported manifest while preserving identity and label authority.
- **Matching boundary:** evaluates required claims under coherent bindings. Unrelated objects cannot be combined into a single witness to manufacture a proof.
- **Research boundary:** audits and evaluates patterns, benchmarks, provenance, partitions, leakage, replay results, and research gates.

## The important separations

```text
Dataset label != analyzer observation != derived fact
              != Evidence claim != witness != evaluation outcome
```

A dataset can label a case `BAD`; that label does not force `MATCH`. An analyzer can omit a relation; the omission does not prove the relation is absent. See [Evidence model](evidence-model.md) for outcome semantics and [Dataset integration](dataset-integration.md) for material identity.

## Artifacts and versions

The package version is `1.0.0`; the current public artifact schema version is `1.0`. They serve different purposes. Schemas live in `schemas/`; reference artifacts live in `examples/`. Pattern migration normalizes a supported representation to the current contract but is not semantic certification; review and re-evaluate migrated patterns.

## Failure boundaries

A valid JSON file can still be semantically incomplete. A successful analyzer process can omit a relation needed by a claim. Keep missing executables, failed parse/export, timeouts, candidate truncation, witness rejection, and complete non-matches distinguishable. EvidenceLab is not a sandbox for hostile code; isolate analyzers and apply host/container limits. See [Security model](security-model.md).
