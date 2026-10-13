# Security model

EvidenceLab validates and transforms research artifacts. It is **not** a sandbox for executing hostile code, and it does not guarantee that an external analyzer is safe against arbitrary input. Security depends on how source files, downloads, analyzers, and generated artifacts are handled on the host.

## Treat inputs as untrusted

This includes source repositories/archives; JSON, JSONL, CSV, XML/GraphML, GraphSON, SARIF, and TEF; dataset mappings and benchmark manifests; graph properties; registry entries; hidden bundles; and third-party reports. The GraphML parser rejects DTD/entity declarations and declarative mappings reject absolute artifact paths or paths escaping `source_root`. These controls reduce specific risks; they are not a universal guarantee that an input is safe.

## Isolate analyzers

Joern and other analyzers can consume substantial CPU, memory, disk, and time. Use a container, VM, or dedicated account with CPU, memory, process, and wall-clock limits; a bounded writable output directory and read-only source mounts when possible; network disabled unless needed for a documented step; no production credentials, SSH keys, cloud tokens, or unrelated private files; and a cleanup plan for temporary graphs and generated binaries.

Do not run untrusted build scripts with elevated privileges merely to make analysis succeed.

## Integrity is not semantic trust

A digest detects byte changes relative to a known digest. A manifest records the identity asserted at capture time. Neither proves a label is correct, a source URL is truthful, or an analyzer found every relevant relation. Schema validity is not research validity, a successful Joern process is not proof of graph completeness, and a sealed hidden bundle is not proof of independent custody.

## Secrets and responsible handling

Never commit HMAC keys, credentials, restricted source, proprietary datasets, or evaluator-only cases. Do not write a secret into a command log or manifest. Confirm redistribution rights before bundling data. If a result suggests a real vulnerability, follow the affected project's responsible disclosure process.

Keep infrastructure failure, analysis incompleteness, and vulnerability outcomes separate. A missing executable, timeout, parse/export failure, or unresolved call must not be relabeled as safe. See [Troubleshooting](troubleshooting.md) and [Reproducibility](reproducibility.md).
