# Research task specification

## Objective

A task should specify a falsifiable vulnerability or behavior question and the evidence required to investigate it. A weakness identifier alone is not a sufficient task definition.

## Required fields

Record:

- task ID and title;
- research question and hypothesis;
- CWE or other taxonomy references where applicable;
- supported language(s), source types, build assumptions, and program scope;
- analyzer or observation providers and the artifact outputs required;
- experimental-material sources, versions, license constraints, and label authority;
- expected positive, negative, unknown, and counter-evidence cases;
- the Evidence Family or definitions expected from the researcher;
- evaluation profile and acceptance criteria;
- split and independence rules;
- runtime, memory, and other resource constraints;
- deliverable paths and reproducibility requirements;
- known risks, exclusions, and open questions.

## Required researcher workflow

1. Review relevant weakness definitions and references.
2. Investigate sample cases before authoring the final Pattern.
3. Preserve raw observations, analyzer output, and exact commands.
4. Record derivations separately from raw observations.
5. Implement the Evidence definition in ELS and validate it.
6. Build positive, negative, unknown, and counter-evidence cases.
7. Test mutations that isolate semantic dimensions.
8. Audit identity, source lineage, duplicate leakage, and split structure.
9. Run the required profile and preserve per-case outputs.
10. Document failures, unsupported cases, and assumptions.
11. Freeze hashes and deliver a reproducibility bundle.

## A submission is not research-grade when

- the semantics rely only on a name or signature with no required relationship;
- the definition has no representative negative or counter-evidence tests;
- missing observations are silently treated as negative results;
- input labels or derived facts have no traceable authority;
- duplicate or mutation-related cases cross partitions without justification;
- a development profile is presented as external or publication-grade validation;
- the result cannot be reconstructed from the saved artifacts and metadata.

## Promotion

Promote a definition from exploration to research-grade evaluation only when the assumptions are explicit, a falsification-oriented case set exists, witness and counter-evidence behavior is reviewed, and the selected profile's gates are met using appropriate material. Promotion is a research decision supported by evidence, not an automatic side effect of a successful command.
