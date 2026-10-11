# Researcher protocol

## Task receipt

Every research task should state its objective, CWE or behavioral scope, language(s), analyzer/observation substrate, expected artifact forms, evaluation profile, allowed datasets, resource constraints, and publication or submission criteria. Use `task.json` or the task-specification document to record this contract.

## Investigation phase

1. Read the weakness definition and relevant source references.
2. Inspect positive and safe examples with materially different structures.
3. Capture analyzer artifacts and preserve commands, versions, logs, and hashes.
4. Form explicit hypotheses about identities, flows, control conditions, and quantitative relations.
5. Record observations and derivations rather than compressing all reasoning into a rule name.
6. Record what evidence would disprove each hypothesis and what missing information would leave it unknown.

Do not begin by tuning a rule around one API or filename. A name-based selector can be a candidate generator, but generally does not prove the required behavior by itself.

## Pattern phase

The Evidence definition should answer:

- What objects and operations must exist?
- Which source, destination, object, call, and value bindings are required?
- Which relations connect those bindings?
- Which directly observed facts are used?
- Which facts are derived, and how can those derivations be replayed?
- What conditions refute or qualify a candidate witness?
- What happens when the graph or analysis is incomplete?
- Which program variants are explicitly out of scope?

## Validation phase

Validation should include pattern audit, benchmark audit, positive/negative/unknown coverage, one-dimension mutations, same-witness counter-evidence, witness replay, split and leakage controls, provenance checks, and independent test material. Choose profile strictness according to the intended claim. Never edit an evaluator profile merely to make a failed scientific gate disappear without documenting the changed standard.

## Weak research signals

- A large number of nearly duplicated generated cases with few independent repositories.
- A single aggregate score without per-case errors and class counts.
- No examples in which the analyzer is incomplete.
- Labels inferred from naming patterns but reported as authoritative.
- No preserved source or graph digest.
- Pattern semantics tied to one raw analyzer label while advertised as analyzer-independent.
- A `PASS` result treated as proof of generalization beyond the measured population.

## Freeze and handoff

Before handoff, freeze source and artifact hashes, exact commands, environment/tool versions, dataset identity, case identities, splits, the Pattern, profile, full result bundle, and a limitations statement. Supply a reproduction command and distinguish executed tests from skipped external integrations.
