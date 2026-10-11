# Benchmark design and validation

## Purpose

A benchmark tests whether an Evidence definition behaves as expected over deliberately selected cases. A benchmark is only as useful as its identities, truth assignments, coverage, independent structure, and source provenance. A large case count alone does not establish validity.

## Required case classes

### Positive cases

Cases where the target semantic condition is present and where the required graph facts should be observable. Include more than one coding shape, project structure, API form, or call path when those differences are relevant to the claimed scope.

### Negative cases

Cases where a superficially similar operation is safe or outside the Evidence definition's target. Examples include bounded extents, validated lengths, distinct objects, safe APIs, correct guards, or different storage lifetimes. Avoid negatives that differ only by an irrelevant spelling change.

### Unknown or incomplete cases

Cases where the source, metadata, or analysis cannot support a definitive answer. Examples include missing types, truncated graph export, data-flow timeout, unresolved external behavior, or a test whose ground-truth authority is ambiguous. Do not use `UNKNOWN` as a miscellaneous bucket for cases that are simply inconvenient to classify; document why a decision is not justified.

### Counter-evidence cases

Cases that specifically challenge a proposed witness by satisfying a refuting or qualifying condition. Counter-evidence should bind to the candidate's objects and control conditions rather than applying as an unrelated global filter.

## Dimension coverage

For a memory-write family, independently vary operation, source, destination object, capacity, extent, object identity, aliasing, control guards, interprocedural flow, type information, and analysis completeness where applicable. Other CWE families need their own dimensions. The Evidence taxonomy provides a starting point; it is not a substitute for a threat or semantic model.

## One-dimension mutations

A useful mutation changes one semantically relevant dimension while keeping other conditions as stable as practical. Expected examples:

- make a write extent bounded without changing the destination;
- change the destination object while preserving the source;
- introduce or remove an effective bounds check;
- change object storage lifetime;
- break a data-flow relation;
- remove required type or capacity information to create an unknown case.

Record original case identity, mutation recipe, changed lines/files, expected semantics, and mutation lineage. Mutation-generated examples are useful for controlled experiments but are not independent real-world projects.

## Independence and leakage

Choose a split based on the intended claim:

- repository split for repository-level generalization;
- project split when project identity is the relevant grouping;
- CVE grouping for vulnerability-instance independence;
- mutation grouping so descendants of one seed do not cross partitions;
- chronological split for a time-forward evaluation question.

Run `leakage-audit`, `leakage-audit-manifest`, `lineage-audit`, and `split-audit` as applicable. A deterministic seed makes a split reproducible but does not make it statistically independent if related source cases cross partitions.

## Metrics and uncertainty

Report the confusion matrix and the denominator behind each metric. Do not count `UNKNOWN`, infrastructure failures, or incomplete analysis as a false negative or true negative without an explicit evaluation policy. Report coverage and missing cases next to precision/recall/specificity. Add witness validity, counter-evidence behavior, localization, and performance when they matter to the research question.

Confidence intervals should reflect the independent sampling unit. Thousands of generated mutations from a small number of repositories do not provide the same evidence of generalization as independent projects.

## Hidden evaluation

Hidden benchmarks reduce direct tuning to the evaluator's cases only if the hidden set is actually controlled by an independent evaluator and was not used during design or debugging. A local bundle labeled hidden is not automatically independent. Preserve origin, custody, sealing method, key management, and verification output. The `hidden-seal` and `hidden-verify` commands help with bundle integrity but cannot establish honest custody on their own.

## Quality gates

Use `benchmark-quality`, `benchmark-audit`, `research-readiness`, and profile-driven checks. The selected profile should state its minimum case counts, labels, datasets, repositories/projects, splits, dimensions, and metric thresholds. Explain the assumptions behind those thresholds and report failed gates without hiding them.

```bash
python -m evidencelab benchmark-quality \
  --benchmark path/to/benchmark.json \
  --min-cases 120 \
  --min-positive 40 \
  --min-negative 40 \
  --min-unknown 20
```

The exact gate requirements depend on the profile and research claim. Passing a development profile is not the same as passing a publication profile.
