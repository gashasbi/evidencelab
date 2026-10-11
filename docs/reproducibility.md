# Reproducibility contract

## Definition

A result is reproducible when an independent researcher can reconstruct its input artifacts and execution configuration and either reproduce the same Evidence decision or independently validate the stored witness. Reproducibility is different from replication: replication tests whether a result persists on new material.

## Required identities

Record, when applicable:

- EvidenceLab package version and schema contract version;
- repository URL, commit, and local modifications;
- Python version, operating system, and relevant runtime configuration;
- analyzer name, exact version/build, and installation source;
- original dataset/project identity, release/version, URL, license, and archive digest;
- case ID and original record identity;
- source code hash, graph hash, and all derived-artifact hashes;
- source mapping/adapter version and digest;
- ELS source digest, compiled Pattern ID/version/digest, and evaluation profile digest;
- commands, timeouts, slice depth, filters, environment-dependent settings, and return codes;
- benchmark identity, split strategy, grouping field, seed, split manifests, and mutation lineage;
- result status, proof states, witness bindings, counter-evidence, completeness, and warnings.

Do not record secrets or credentials in a public experiment manifest. Secret-dependent operations should record the credential identity or key fingerprint if appropriate, not the secret itself.

## Artifact inventory

Create an artifact index:

```bash
python -m evidencelab provenance-index \
  --root research/cwe-121 \
  --out research/provenance/artifacts.json
```

Verify it after copying or archiving the workspace:

```bash
python -m evidencelab provenance-verify \
  --manifest research/provenance/artifacts.json
```

The inventory makes file changes detectable. It does not prove that an upstream dataset was correctly labeled or that the initial artifact was truthful.

## Experiment ledger

Record experiment activities with the relevant hypothesis, tool, exact command, result, cases, and notes:

```bash
python -m evidencelab research-record \
  --root research/cwe-121 \
  --hypothesis "H1: input reaches the bounded write operation" \
  --tool Joern \
  --command 'joern-slice data-flow --slice-depth 8 ...' \
  --result PASS \
  --notes "Observed output retained at artifacts/capture-001"
```

Record raw observations and derived facts separately where those commands are part of the research project. Link observations to their source artifact and derivations to the inputs and method used.

## Bundle and verification

Create a review bundle after deciding which data may be distributed:

```bash
python -m evidencelab research-bundle \
  --root research/cwe-121 \
  --out /tmp/cwe-121-reproduction.tar.gz
```

Hidden material and external data are controlled by explicit opt-in flags. Inspect the bundle before sharing it to ensure it does not contain prohibited source, licensed files, credentials, keys, or private data.

## Reproduction versus replication

- **Reproduction:** same pattern, graph/material, configuration, versions, and command path.
- **Witness replay:** fixed stored witness checked against a graph and pattern without running candidate discovery again.
- **Replication:** new cases, repositories, projects, or time periods test whether the conclusion generalizes.
- **External validation:** a distinct evaluation process, ideally controlled by an independent evaluator, assesses the claim on held-out material.

A matching hash is useful for identity and integrity; it is not proof of semantic correctness or independent origin.
