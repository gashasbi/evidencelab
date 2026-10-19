# Security model

EvidenceLab validates and transforms research artifacts. It is **not a sandbox for executing hostile code**, and it does not guarantee that an external analyzer is safe against arbitrary input. Security depends on how source files, downloads, analyzers, and generated artifacts are handled on the host.

## Treat inputs as untrusted

Inputs can include source repositories and archives; JSON, JSONL, CSV, XML/GraphML, GraphSON, SARIF, and TEF files; dataset mappings and benchmark manifests; graph properties; registry entries; hidden bundles; and third-party reports.

Some format-specific controls reduce particular risks—for example, the GraphML parser rejects DTD/entity declarations, and declarative mappings restrict paths to a declared source root. These controls are not a universal guarantee that an input is safe.

## Isolate analyzers

Joern and other analyzers may consume substantial CPU, memory, disk, and time. For untrusted input, use a VM, container, or dedicated account with:

- CPU, memory, process-count, disk, and wall-clock limits;
- a bounded writable output directory and read-only source mounts where practical;
- network access disabled unless a documented step requires it;
- no production credentials, SSH keys, cloud tokens, or unrelated private files;
- a cleanup plan for temporary graphs and generated binaries.

Do not run untrusted build scripts with elevated privileges merely to make analysis succeed.

## Integrity is not semantic trust

A digest detects byte changes relative to a known digest. A manifest records the identity asserted at capture time. Neither proves that a label is correct, a source URL is truthful, or an analyzer found every relevant relation.

Schema validity is not research validity. A successful Joern process is not proof of complete graph semantics. A sealed hidden bundle is not proof of independent custody.

## Secrets, licenses, and disclosure

Never commit HMAC keys, credentials, restricted source, proprietary datasets, or evaluator-only cases. Do not write secrets into command logs or manifests. Confirm redistribution rights before bundling data. If results suggest a real vulnerability, follow the affected project's responsible-disclosure process.

Keep infrastructure failure, analysis incompleteness, and vulnerability outcomes distinct. A missing executable, timeout, parse/export failure, or unresolved call must not be relabeled as safe.

See [Troubleshooting](troubleshooting.md) and [Reproducibility](reproducibility.md).
