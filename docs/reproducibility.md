# Reproducibility and witness replay

Reproduction reconstructs a result from the same inputs, software, configuration, and commands. Replication asks whether the conclusion holds on new material. A matching hash detects byte-level changes relative to a known digest; it does not prove semantic correctness or independent origin.

## Record identities

Record the items relevant to the experiment: EvidenceLab/package and artifact-schema versions; repository URL, commit, and local changes; Python/OS and analyzer release/build/configuration; dataset/project release or commit, license, case IDs, source hashes, and mapping/adapter digest; ELS digest, Pattern identity/version/digest, evaluation profile, graph and derived artifact digests; commands, timeouts, filters, depth/binding limits, return codes and warnings; benchmark/split identities, grouping strategy, seed, mutation lineage, per-case outcome and completeness; and witness bindings, counter-evidence, and replay results.

Do not publish secrets or credentials. Record a key fingerprint or identifier where necessary, not the secret itself.

## Index and verify artifacts

```bash
python -m evidencelab provenance-index \
  --root research/cwe-121 \
  --out research/provenance/artifacts.json

python -m evidencelab provenance-verify \
  --manifest research/provenance/artifacts.json
```

The inventory detects changes to indexed files; it cannot establish that an upstream label was correct or that the starting material was truthful.

## Record activities

```bash
python -m evidencelab research-record \
  --root research/cwe-121 \
  --hypothesis "Input reaches the bounded write operation" \
  --tool Joern \
  --command 'joern-slice data-flow ...' \
  --result PASS \
  --notes "Capture retained under artifacts/capture-001"
```

When observations and derivations are recorded, keep raw observations separate from derived facts and identify their inputs and method.

## Replay a stored witness

```bash
python -m evidencelab witness-replay \
  --report path/to/case-report.json \
  --graph path/to/canonical-graph.json \
  --pattern path/to/pattern.json

python -m evidencelab witness-replay-batch \
  --results-dir path/to/evaluation-results \
  --pattern path/to/pattern.json
```

Replay re-evaluates a previously bound witness without running candidate discovery again. It can reveal changed artifacts, invalid IDs, or claims that no longer hold. It cannot find an unstored witness, compensate for missing graph facts, or substitute for full benchmark evaluation.

## Bundle and hand off

```bash
python -m evidencelab research-bundle \
  --root research/cwe-121 \
  --out /tmp/cwe-121-reproduction.tar.gz
```

Hidden and external data are included only with explicit opt-in flags. Inspect a bundle before sharing it for licenses, secrets, private source, keys, and evaluator-only cases.

- **Reproduction:** same inputs, versions, configuration, and command path.
- **Witness replay:** recheck one stored binding against a graph and Pattern.
- **Replication:** test the claim on new cases, projects, repositories, or time periods.
- **External validation:** evaluation on held-out material with appropriate independence, ideally by an independent evaluator.
