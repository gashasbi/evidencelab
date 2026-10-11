# Research methodology

EvidenceLab supports a transparent workflow from hypothesis formation to an independently reviewable Evidence artifact. The researcher owns the semantic interpretation; the platform supplies executable contracts, repeatable capture, matching, provenance, and evaluation controls.

## Stage A: define the boundary

Write a question that can be falsified. Identify the weakness or behavior, supported languages, program constructs in scope, expected deployment or analysis context, and known exclusions. Avoid a definition such as "detect all buffer overflows" without a scope that can be tested.

## Stage B: state hypotheses

Separate the target condition from the analyzer query. For each hypothesis, record what entities and relationships must exist, what would refute it, and what information would leave it unresolved.

## Stage C: gather observations

Use Joern or another analyzer to capture raw artifacts and queries. Keep the original source, command, tool version, stdout/stderr, export files, and checksums. A query result is an observation, not automatically a semantic conclusion.

## Stage D: record derivations

State how each derived fact is calculated from identified observations. Preserve assumptions and replay information where feasible. If a value depends on an external function summary, an unknown type, or a heuristic, record that dependency rather than labeling the value as fully proven.

## Stage E: encode the Evidence definition

Author the definition in ELS, validate and compile it, and review the compiled Pattern. Prefer canonical semantics when the intended claim should be analyzer-independent. Set conservative policies and explicit path/candidate budgets.

## Stage F: falsify the definition

Use positive cases, safe negatives, counter-evidence cases, and unknown/incomplete cases. Build tests that isolate one semantic dimension at a time. Inspect the binding and claims of each witness instead of reviewing only the final status.

## Stage G: construct experimental material

Record exact dataset/project snapshots, case identities, labels and their authority, source hashes, mapping code, exclusions, and provenance. Use declarative mappings for simple records and an adapter for complex upstream formats. Do not silently replace unknown labels with heuristic ones.

## Stage H: control leakage

Group related cases by source repository, project, CVE, mutation ancestry, or another relevant identity before splitting. Use chronological splits for time-forward claims. Audit near duplicates and source lineage, then inspect overlap warnings manually.

## Stage I: evaluate

Run the chosen profile. Persist per-case outcomes and matcher artifacts. Report counts and denominators, unknown/infrastructure rates, witness replay outcomes, counter-evidence behavior, localization, runtime, and resource bounds as relevant. Do not rely on aggregate scores alone.

## Stage J: validate externally

Use held-out repositories, projects, or a corpus controlled by an independent evaluator to test generalization. Hidden sealing is an integrity mechanism, not a substitute for evaluator independence.

## Stage K: freeze for reproduction

Hash the ELS file, compiled Pattern, source artifacts, graph exports, benchmark manifests, split manifests, profile, code revision, and evaluation results. Record tool and runtime versions plus the exact commands. Bundle the minimal artifacts needed for another researcher to reproduce or independently replay the result.

## Recommended commands

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els
python -m evidencelab audit --pattern path/to/pattern.json --json
python -m evidencelab benchmark-audit --benchmark path/to/benchmark.json --pattern path/to/pattern.json
python -m evidencelab research-check --root research/cwe-121 --profile profiles/research-grade-c-cpp-joern.json --summary
python -m evidencelab research-readiness --root research/cwe-121 --profile profiles/research-grade-c-cpp-joern.json
```

Use flags that match the selected profile and your actual package layout. These commands are not interchangeable: pattern audit, benchmark audit, research readiness, research evaluation, and hidden evaluation answer different questions.
