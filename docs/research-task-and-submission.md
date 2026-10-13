# Research task and submission

A task specifies the question and acceptance criteria before a researcher tunes an Evidence definition. A submission is the reviewable package handed off at the end. Keep the task, Evidence, material, evaluation, and provenance identities consistent.

## Task specification

Record, as applicable: task ID/title, falsifiable question, hypothesis, CWE/taxonomy references; language, program scope, assumptions, and exclusions; analyzer/observation provider and required artifacts; allowed dataset sources, versions, licenses, label authority, and source identity; expected positive, negative, unknown, and counter-evidence cases; Evidence family/pattern, evaluation profile, acceptance criteria, resource budget, split/independence requirements, deliverable paths, and reproducibility needs.

A weakness ID alone is not a complete task definition. A successful command or a passing development gate is not an automatic promotion to research-grade evidence.

## Recommended submission layout

Include only artifacts relevant to the task, but retain a consistent identity chain:

```text
submission/
  task.json
  evidence/        ELS, compiled Pattern, tests
  material/       dataset manifest, mapping, source identities
  graphs/         graph/capture manifests and permitted analyzer artifacts
  experiments/    observations, derivations, activity ledger
  evaluation/     profile, benchmark, splits, per-case results, replay, summary
  provenance/     artifact inventory
  notes/           assumptions and limitations
```

Do not include credentials, HMAC keys, restricted hidden cases, proprietary source, or datasets that cannot be redistributed.

## Create and validate a submission

```bash
python -m evidencelab make-submission \
  --root research/cwe-121 \
  --cwe CWE-121 \
  --pattern research/cwe-121/evidence-pattern.json \
  --graph research/cwe-121/graphs/vulnerable.json \
  --out /tmp/cwe-121-submission.json

python -m evidencelab validate-submission \
  --submission /tmp/cwe-121-submission.json \
  --profile profiles/research-submission-strict-c-cpp-joern.json
```

Use paths from your actual workspace and inspect the generated manifest; this example is not a complete publication package. For detailed option sets, run `--help`.

## Required disclosures

State the hypothesis and scope, exclusions, input identities and label authority, Evidence/Pattern digests, analyzer/version/settings, completeness/unknowns, split strategy, leakage checks, per-case counts, replay findings, limitations, and which gates actually ran. Distinguish shipped reference demonstrations from independent external evaluation.

A handoff is not research-grade if required relations are not justified, safe/unknown counterexamples are absent, labels/derivations lack provenance, related cases leak across partitions without explanation, or results cannot be reconstructed from retained artifacts.
