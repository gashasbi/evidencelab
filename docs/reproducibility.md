# Reproducibility and witness replay

**Reproduction** repeats a result with the same inputs, versions, configuration, and commands. **Replication** tests whether the conclusion holds on new material. A matching hash detects byte-level changes relative to a known digest; it does not prove semantic correctness or independent origin.

## Record the experimental identity

For each run, preserve as applicable:

- EvidenceLab package version, schema version, repository commit, and local modifications;
- Python, OS, analyzer release/build, and relevant configuration;
- dataset/project release or commit, license, case IDs, source hashes, label authority, and mapping/adapter digest;
- ELS and Pattern identity/version/digest, evaluation profile, graph and derived-artifact digests;
- exact commands, timeouts, filters, depth/binding limits, return codes, warnings, and completeness state;
- benchmark and split identities, grouping strategy, seed, mutation lineage, per-case outcome, and witness/replay artifacts.

Do not put credentials, secrets, or private keys into manifests or logs.

## Build and verify an artifact inventory

```bash
python -m evidencelab provenance-index \
  --root research/cwe-121 \
  --out research/provenance/artifacts.json

python -m evidencelab provenance-verify \
  --manifest research/provenance/artifacts.json
```

Use a project-local path appropriate to your workspace. The inventory can detect changes to indexed files; it cannot prove that upstream labels are correct or that source metadata is truthful.

## Record an experiment

```bash
python -m evidencelab research-record \
  --root research/cwe-121 \
  --hypothesis "Input reaches the bounded write operation" \
  --tool Joern \
  --command 'joern-slice data-flow ...' \
  --result PASS \
  --notes "Capture retained under artifacts/capture-001"
```

Keep raw observations separate from derived facts and identify the inputs and method for each derivation.

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

Replay checks a previously bound witness without repeating candidate discovery. It can expose changed artifacts, invalid IDs, or claims that no longer hold. It cannot discover an unstored witness, compensate for missing graph facts, or substitute for a full benchmark evaluation.

## Bundle and hand off

```bash
python -m evidencelab research-bundle \
  --root research/cwe-121 \
  --out /tmp/cwe-121-reproduction.tar.gz
```

Inspect any bundle before sharing it. Check licensing, credentials, private source, external data, and evaluator-only material. Hidden or external data should only be included when explicitly intended and authorized.

## Use precise language

- **Artifact integrity:** indexed bytes match the expected digest.
- **Witness replay:** a stored binding is rechecked against the graph and Pattern.
- **Reproduction:** the same experiment is repeated under recorded conditions.
- **Replication/external validation:** the claim is tested on new or held-out material under an appropriate evaluation design.

These are related but not interchangeable guarantees.
