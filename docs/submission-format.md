# Research submission format

## Purpose

A submission is a self-contained, reviewable research package that allows EvidenceLab to validate the artifact structure and run the configured checks. The submission should expose the evidence and provenance behind the claim, not only a final score.

## Recommended contents

```text
submission/
  task.json
  evidence/
    evidence.els
    pattern.json
    tests/
  material/
    dataset-manifest.json
    mapping.json
    source-identities.json
  graphs/ or captures/
    capture-manifest.json
    analyzer-artifacts/ (when redistribution is permitted)
  experiments/
    observations.jsonl
    derivations.jsonl
    experiment-ledger.jsonl
  evaluation/
    profile.json
    benchmark.json
    split-manifests/
    per-case-results/
    witness-replay/
    summary.json
  provenance/
    artifacts.json
  notes/
    assumptions.md
    limitations.md
```

Include only the fields and artifacts relevant to the task, but preserve the same semantic identities across manifests and reports. Do not include credentials, HMAC keys, restricted hidden cases, or external data that the submitter is not authorized to redistribute.

## Create and validate a submission

Use `make-submission` to generate a submission manifest from a research workspace, CWE, Evidence Pattern, and one or more graphs. Then validate the submission against the intended profile:

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

The correct paths depend on the workspace produced by the researcher; inspect the generated manifest rather than assuming this example is a complete publication package.

## Required disclosures

State the hypothesis, supported scope, exclusions, source-data identity, label authority, analyzer version, Evidence and Pattern digests, incomplete analysis, split method, leakage checks, per-case evaluation counts, witness replay findings, limitations, and which gates were or were not run. Distinguish source-derived demonstrations from independent external evaluation.
