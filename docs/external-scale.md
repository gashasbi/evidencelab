# External-scale evaluation

## Goal

External-scale evaluation asks whether an Evidence definition remains useful beyond the reference cases that shaped it. This is different from whether the software installs, an ELS file validates, or a small unit suite passes.

## Conditions for a defensible claim

Before claiming external scale, establish:

1. **Independent identity:** cases originate from independently identified repositories, projects, commits, CVEs, or evaluator-controlled material appropriate to the claim.
2. **Source provenance:** each corpus snapshot and mapping is versioned and hashed.
3. **Label authority:** every reported expectation has a documented authority; inferred labels remain explicitly heuristic.
4. **Semantic coverage:** the data exercises the dimensions required by the Evidence definition, including safe counterexamples and unknown/incomplete analysis where relevant.
5. **Leakage control:** near duplicates, mutation descendants, project overlap, and chronological boundaries have been audited.
6. **Analyzer disclosure:** versions, queries, settings, depth limits, unsupported features, and failed cases are reported.
7. **Case-level auditability:** outcomes, witness references, replay status, and infrastructure failures are retained per case.
8. **Uncertainty reporting:** unknown and partial outcomes are reported separately from definitive non-matches.
9. **Independent review:** the validation set is not used to tune the definition if the claim is that it is held out.

## What does not establish scale

A high record count from one source, generated mutations of a few seeds, or hundreds of files in one repository is not equivalent to hundreds of independent projects. A large corpus with unclear labels or no provenance is not a strong validation set. A local hidden bundle is not an evaluator-controlled hidden set merely because its filename includes `hidden`.

## Profile-based gates

Use profile-driven readiness and evaluation to convert research requirements into explicit checks:

```bash
python -m evidencelab research-readiness \
  --root research/cwe-121 \
  --profile profiles/research-grade-c-cpp-joern.json \
  --out /tmp/readiness.json

python -m evidencelab research-evaluate \
  --root research/cwe-121 \
  --profile profiles/research-grade-c-cpp-joern.json \
  --out /tmp/evaluation
```

Use the exact profile appropriate to the claim. A development profile checks the development workflow; it is not evidence of independent external generalization.
