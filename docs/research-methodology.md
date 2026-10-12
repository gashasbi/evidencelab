# Research methodology

Use this workflow when the goal is to make a defensible claim about a researcher-authored Evidence definition. The software can make the definition executable and results auditable; it cannot decide the research semantics or establish external validity on its own.

## 1. Define a falsifiable scope

State the behavior/weakness, supported languages and constructs, program context, expected analyzer substrate, assumptions, exclusions, and intended claim. A CWE ID is a taxonomy reference, not an executable proof rule. Avoid goals such as “detect all buffer overflows” without a testable scope.

## 2. Investigate before writing a rule

Inspect materially different positive and safe cases. Capture raw analyzer artifacts, exact commands, versions, logs, and hashes. Separate:

- observations directly present in source or analyzer output;
- derived facts and the method/inputs used to derive them;
- claims the researcher requires the Evidence engine to prove;
- missing facts that should leave the case unresolved.

A name or signature can nominate a candidate, but does not by itself prove behavior or a causal relation.

## 3. Encode and falsify the Evidence

Author ELS for the intended bindings, claims, coherent witness, counter-evidence, uncertainty policies, and execution budgets. Validate and compile it, then review the compiled Pattern.

Build a case set with positive, safe-negative, unknown/incomplete, and counter-evidence cases. Add one-dimension mutations where useful (for example, change only the extent, object, guard, or flow relation). Inspect bindings and claim-level results, not only the top-level status. Test that timeouts, missing properties, and candidate truncation do not become definitive negatives.

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els
python -m evidencelab evidence compile --spec path/to/evidence.els --out /tmp/pattern.json
python -m evidencelab evidence run --spec path/to/evidence.els --graph path/to/canonical-graph.json --out /tmp/result.json
```

For syntax details, see [ELS reference](evidence-dsl.md); for status semantics, see [Evidence model](evidence-model.md).

## 4. Build trustworthy experimental material

Choose an exact dataset snapshot, repository commit, suite, or archive. Record source identity, license, label authority, case IDs, source hashes, mapping/adapter version, exclusions, and transformations. Keep unknown labels unknown unless there is a documented reason and authority to classify them. Use [Dataset integration](dataset-integration.md) for importer and mapping contracts.

Before importing a full dataset, validate and preview representative records. Inspect the imported case IDs, source references, labels, and relationships. A large imported corpus is not automatically a valid benchmark.

## 5. Control overlap and leakage

Select a split strategy based on the intended claim: repository, project, CVE, mutation ancestry, or chronology. Keep related cases and mutation descendants in the same partition where relevant. Run `leakage-audit`, `leakage-audit-manifest`, `lineage-audit`, and `split-audit` as appropriate, and inspect warnings manually. A deterministic seed makes a split repeatable; it does not make related cases independent.

## 6. Evaluate and report

Use the profile that matches the claim. Keep per-case results and witness artifacts. Report counts and denominators behind each metric; `UNKNOWN`, `PARTIAL`, infrastructure-error, and incomplete-analysis cases; witness replay and counter-evidence; source/project identity, split design, leakage checks, analyzer/version/settings; and runtime/resource budgets and limitations where relevant.

Confidence intervals should reflect the independent sampling unit. Hundreds of mutations from a few repositories are not hundreds of independent projects. Do not remove failed/time-out cases silently from denominators.

## 7. Validate externally and freeze

A publication or generalization claim needs suitable held-out material and an evaluation process not used to tune the definition. A development profile is not a publication profile. A local hidden bundle is not evaluator-controlled simply because it is named “hidden”; sealing can help detect tampering but cannot establish custody.

Freeze the ELS and Pattern, source/graph and dataset digests, profile, split manifests, tool/runtime versions, exact commands, per-case outputs, witness replay, and limitations statement. Use [Reproducibility](reproducibility.md) for artifact inventories and bundles and [Research task and submission](research-task-and-submission.md) for handoff structure.

## Weak evidence for a research claim

None of the following is sufficient alone: a passing unit suite; a schema-valid Pattern; one positive case; many duplicate or mutation-derived cases; a label inferred from a filename; a single aggregate score with no denominator; a successful Joern process; a local “hidden” archive; or a `PASS` from a development gate.
