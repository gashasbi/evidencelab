# Joern integration

EvidenceLab integrates with Joern as an external analyzer. Joern is installed and versioned separately; it is not bundled into the Python package. You do not need Joern to run the bundled prebuilt-graph quickstart.

## What the integration does

Depending on options and tool availability, EvidenceLab can invoke Joern tools to:

- parse source into a CPG artifact (`joern-parse`);
- export GraphML and, unless disabled, GraphSON (`joern-export`);
- optionally produce a JSON data-flow slice (`joern-slice`);
- preserve command results, source identity/hash, tool-version information when detectable, and capture status in a capture manifest.

EvidenceLab parses and normalizes supported artifacts and evaluates Evidence definitions over them. It does not replace Joern's analysis engine. Analyzer success does not guarantee complete semantic coverage.

## Install Joern separately

Follow the official documentation for the release you choose:

- [Joern documentation](https://docs.joern.io/)
- [Installation](https://docs.joern.io/installation/)
- [Quickstart](https://docs.joern.io/quickstart/)
- [Releases](https://github.com/joernio/joern/releases)

Joern's requirements change independently of EvidenceLab. Pin a specific release for reproducible work and record its release tag, installation source, and checksum where available. Do not rely on a mutable `latest` URL as the only record of the tool version.

## Verify executables

The integration may use these executables:

| Executable | Role |
|---|---|
| `joern-parse` | Parse source and create a CPG. |
| `joern-export` | Export graph representations. |
| `joern-slice` | Create a data-flow slice when requested. |
| `joern` | Version diagnostics and interactive investigation where available. |

Check the local installation:

```bash
command -v joern
command -v joern-parse
command -v joern-export
command -v joern-slice
python -m evidencelab doctor --joern
```

Finding an executable on `PATH` proves only that it is discoverable. Run a small capture to check the toolchain end to end.

## Capture a source file

Choose a small source file from the checkout and inspect it before analysis:

```bash
find examples -type f \( -name '*.c' -o -name '*.cpp' \) | sort | head -20
```

Set `SOURCE` to a specific file, then capture to a fresh output directory:

```bash
SOURCE=examples/cwe-121/corpus/source/P02_direct_strcat.c
python -m evidencelab capture \
  --source "$SOURCE" \
  --out /tmp/evidencelab-capture \
  --dataflow-timeout 240 \
  --dataflow-slice-depth 8
```

Use a source path that exists in your checkout. Capture writes analyzer artifacts to its designated output directory; use a fresh directory and do not point it at unrelated files.

The default behavior may request GraphSON and data-flow analysis; inspect `python -m evidencelab capture --help` to see the options accepted by the installed checkout.

## Interpret the capture manifest

Retain `capture-manifest.json` together with the generated graph artifacts and logs. Check:

- source identity and hash;
- tool and command information where available;
- artifact paths and digests;
- capture status and data-flow status;
- warnings, timeouts, and degraded-analysis indicators.

A missing data-flow slice is not evidence that no flow exists. A `DEGRADED`, `FAILED`, or `TIMEOUT` state must remain visible in downstream evaluation. Do not silently treat an incomplete capture as a safe negative.

## Security and reproducibility

Analyze untrusted source in a VM, container, or dedicated account with CPU, memory, disk, process, and wall-clock limits. Do not expose production credentials or private keys to analyzer processes. Record EvidenceLab and Joern versions, source commit/hash, command options, environment, and output digests.

See [Security model](security-model.md), [Reproducibility](reproducibility.md), and [Troubleshooting](troubleshooting.md).
