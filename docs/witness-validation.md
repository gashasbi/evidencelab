# Witness validation and replay

## Why replay matters

A matcher can search a graph for candidate witnesses. After a candidate is stored, witness replay evaluates the already-bound entities again without repeating the candidate discovery process. This separates two failure classes:

- candidate discovery did not find a valid binding;
- a stored binding does not satisfy the Evidence claims under the current graph and Pattern.

Replay strengthens auditability, but it does not establish that the original graph was complete or that the Evidence definition generalizes to new data.

## Structural checks

A useful witness record should identify the Evidence Pattern, graph artifact, bound nodes/edges, claim results, proof states, counter-evidence results, and the final outcome. Validate that the IDs referenced by a stored witness still exist and that the source graph and Pattern identities match the recorded digests.

## Replay one report

```bash
python -m evidencelab witness-replay \
  --report path/to/case-report.json \
  --graph path/to/canonical-graph.json \
  --pattern path/to/pattern.json
```

## Replay stored evaluation reports

```bash
python -m evidencelab witness-replay-batch \
  --results-dir path/to/evaluation-results \
  --pattern path/to/pattern.json
```

Use `--help` for the exact fields expected by the currently installed release. Retain replay output with the original evaluation artifacts.

## Validate a benchmark's witnesses

Use `witness-validate` to check stored reports or expected matches across a benchmark. Set the report/benchmark/pattern inputs to the artifact types present in your run. A failed replay should be classified and investigated rather than hidden by re-running the matcher and keeping only a new report.

## Interpretation

- A passing replay means the recorded binding satisfies the checked claims for the supplied graph and Pattern.
- A failed replay can indicate changed artifacts, invalid stored IDs, a mismatch between the stored result and the current Pattern, or an actual witness defect.
- A replay cannot discover a witness that was never stored.
- A replay over a partial graph cannot prove facts absent from that graph.
- A replay result is not an external validation metric by itself.
