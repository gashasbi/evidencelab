# Benchmark design and evaluation

A benchmark tests whether an Evidence definition behaves as expected over deliberately selected cases. It is only as useful as case identity, label authority, semantic coverage, independence, and source provenance. Case count alone does not establish validity.

## Required case classes

- **Positive:** the target semantic condition is present and required graph facts should be observable.
- **Negative:** a superficially similar case is safe or outside scope (for example, bounded extent, correct guard, distinct destination, or safe API). Avoid negatives that differ only in spelling.
- **Unknown/incomplete:** input, labels, or analysis cannot support a definitive decision. Record why.
- **Counter-evidence:** a concrete condition that refutes or qualifies the same candidate witness, not an unrelated global filter.

For memory-write claims, vary operation, source, destination, object identity, capacity, extent, aliasing, guards, interprocedural flow, typing, and analysis completeness where those dimensions affect the scope. Other weakness families need their own semantic model.

## Mutations, identity, and leakage

A useful mutation changes one semantically relevant dimension while keeping others as stable as practical. Record the seed case, changed files/lines, recipe, expected semantics, and mutation lineage. Mutations are useful controlled tests but are not independent real-world projects.

Choose splits to match the intended claim: repository/project, CVE, mutation ancestry, or chronological. Audit near duplicates, source lineage, and cross-partition overlap. Do not let related descendants cross partitions without explicit justification.

## Metrics and uncertainty

Report confusion matrices and the denominator for every metric. Keep `UNKNOWN`, infrastructure errors, and incomplete analysis separate from definitive positives/negatives unless an explicit evaluation policy justifies a transformation. Report coverage and missing cases next to precision/recall/specificity. Confidence intervals should reflect independent projects/cases, not the raw number of records when many records are related.

If performance matters, record analyzer and matcher time separately, graph size, candidate/path budgets, resource usage, repetitions, and timeouts. A timeout must not disappear from the results merely because it is inconvenient.

## Hidden evaluation

A hidden set helps reduce tuning only when an independent evaluator controls its selection, custody, and access. A local bundle named “hidden” is not automatically independent. Sealing and HMAC checks can help detect tampering, but do not prove who had access to the data or whether it was used during development.

## Quality gates

Use `benchmark-quality`, `benchmark-audit`, `research-readiness`, and profile-driven checks as appropriate. Profiles should state required case counts, labels, datasets/projects, splits, dimensions, and thresholds; explain why those values support the intended claim. Passing a development profile is not publication-grade external validation.

Example minimum-count gate (change the values only to match the chosen research plan):

```bash
python -m evidencelab benchmark-quality \
  --benchmark path/to/benchmark.json \
  --min-cases 120 --min-positive 40 --min-negative 40 --min-unknown 20
```

## Performance measurements

When runtime/resource cost is part of the claim, measure repeated runs and record hardware, OS/Python/EvidenceLab/analyzer versions, graph size, candidate and path limits, parse/export time, matcher/replay time, memory/disk use where practical, and timeout/failure counts. Keep analyzer startup and I/O separate from matcher time. Do not hide timed-out cases.

```bash
python -m evidencelab performance \
  --benchmark path/to/benchmark.json \
  --pattern path/to/pattern.json \
  --repeats 5
```

Check `python -m evidencelab performance --help` for the installed release's exact options and output behavior. See [Research methodology](research-methodology.md) and [Reproducibility](reproducibility.md).
