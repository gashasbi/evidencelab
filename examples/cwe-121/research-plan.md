# CWE-121 Research Plan — EvidenceLab 1.0.0

## Research question
What graph-observable evidence is sufficient to establish a coherent C/C++ buffer-write witness relevant to CWE-121 while distinguishing proven evidence, counter-evidence, and uncertainty?

## Boundary
This reference package studies two deliberately separate evidence families: fixed-extent writes beyond a proven byte capacity of an automatic local array, and unbounded-copy semantics into an automatic local array. A MATCH is an evidence-pattern match, not runtime exploitability or physical stack-placement proof.

## Method
Joern observations are captured without treating analyzer-specific node/edge syntax as semantic truth. EvidenceLab canonicalizes the graph, derives semantic facts with provenance, binds one coherent witness, evaluates witness-specific counter-evidence, and performs independent fixed-binding replay.

## Reference benchmark
The bundled corpus is a small reference/development corpus. It is intentionally not publication-grade. Publication requires external real-world sources, independent repository/chronological splits, leakage audits, and evaluator-controlled hidden validation.

## Reproducibility
Every committed observation and derivation is hash-chained in `experiments/observations.jsonl` and `experiments/derivations.jsonl`; experiment executions are hash-chained in `experiments/experiment-ledger.jsonl`.
