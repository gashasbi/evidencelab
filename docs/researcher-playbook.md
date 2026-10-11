# Researcher playbook

This page is the compact workflow. Use the linked specifications for detailed semantics and option definitions.

## 1. Define a bounded research question

State the weakness or behavior, target language, program context, assumptions, scope, and exclusions. Use CWE as taxonomy and background, not as the Evidence definition itself.

## 2. Investigate before authoring a rule

Collect structurally different source cases and inspect analyzer artifacts. Identify the causal entities, relationships, quantitative constraints, control conditions, and missing information relevant to the claim. Record counterexamples early.

## 3. Preserve observations and derivations

Retain raw analyzer artifacts and command output. Record derived facts with the input observations and method. If the analysis depends on an approximation, heuristic, library summary, or incomplete call graph, mark that dependency explicitly.

## 4. Author Evidence

Use ELS to define concepts, slots, claims, coherent witnesses, counter-evidence, and uncertainty policies. Compile to the Pattern contract and review the compiled artifact. See [ELS reference](evidence-dsl.md).

## 5. Build a representative test set

Include positive, negative, unknown, counter-evidence, and one-dimension mutation cases. Avoid treating copies or mutations of the same seed as independent projects. Preserve case identity and label authority.

## 6. Audit and evaluate

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els
python -m evidencelab audit --pattern path/to/pattern.json --json
python -m evidencelab benchmark-audit --benchmark path/to/benchmark.json --pattern path/to/pattern.json
python -m evidencelab research-check --root path/to/research --profile path/to/profile.json --summary
```

Then inspect per-case results, witness coherence, counter-evidence, unknowns, performance, leakage, and provenance. Use independent witness replay when stored results contain witnesses.

## 7. Report limitations and freeze

Record known false positives/negatives, unsupported semantic conditions, incomplete cases, split design, data provenance, analyzer/version, and resource bounds. Freeze digests of the pattern, input material, graph artifacts, profile, and results before publishing.

## Weak evidence of a research claim

The following are not sufficient by themselves:

- finding a sink name without a causal relation;
- one positive sample and no safe counterexamples;
- interpreting missing edges as proof of safety;
- using heuristic labels without recording the heuristic;
- combining unrelated graph fragments into one witness;
- tuning on the hidden evaluation set;
- reporting a score with no denominator, source identity, or split information.
