# Joern integration: installation, capture, and validation

Joern is a supported external analyzer integration for EvidenceLab. It is not bundled into EvidenceLab and is not merely a placeholder example. EvidenceLab invokes Joern command-line tools to construct a Code Property Graph (CPG), export graph artifacts, optionally calculate data-flow slices, and record the capture inputs and status. The resulting artifacts are normalized at the EvidenceLab boundary and can be inspected, merged, evaluated, or used by Evidence definitions.

This page describes the integration contract implemented in EvidenceLab 1.0.0. Joern is developed and released separately, so use the official Joern installation instructions and release notes for release-specific requirements.

## 1. What Joern contributes

Joern is a static-analysis platform built around Code Property Graphs. A CPG combines syntax, control-flow, data-flow, and other program properties into a queryable graph. Joern has its own query language and analyzers; EvidenceLab does not replace those capabilities.

In the current integration, Joern supplies:

- a binary CPG produced by `joern-parse`;
- a GraphML export produced by `joern-export`;
- a GraphSON export produced by `joern-export`, unless disabled;
- an optional JSON data-flow slice produced by `joern-slice data-flow`;
- command output, tool-version information when detectable, source hashing, and analysis status preserved in `capture-manifest.json`.

EvidenceLab's role starts at the boundary of these analyzer artifacts: parse supported exports, preserve provenance and completeness metadata, normalize semantic observations, and execute researcher-authored Evidence against the resulting graph. An analyzer's presence or exit code is not a proof that every relevant semantic relation was recovered.

## 2. Official Joern resources

Use primary upstream resources:

- [Joern project](https://joern.io/)
- [Joern documentation overview](https://docs.joern.io/)
- [Installation](https://docs.joern.io/installation/)
- [Quickstart](https://docs.joern.io/quickstart/)
- [Code Property Graph](https://docs.joern.io/code-property-graph/)
- [Graph export](https://docs.joern.io/export/)
- [CPG slicing](https://docs.joern.io/cpg-slicing/)
- [Data-flow steps](https://docs.joern.io/cpgql/data-flow-steps/)
- [Data-flow semantics](https://docs.joern.io/dataflow-semantics/)
- [Release downloads](https://github.com/joernio/joern/releases)

Joern changes independently of EvidenceLab. Pin and record the exact Joern release used in an experiment. Do not base a reproducibility claim on a mutable `latest` installer URL alone.

## 3. Host prerequisites

Use a supported operating system and follow the instructions for the exact Joern release being installed. The current Joern repository README specifies JDK 21; if a release's installation guide states a different tested requirement, follow that release's documentation. For C/C++ analysis, GCC/G++ can help Joern discover and process system headers.

On Ubuntu, a typical starting point is:

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk curl unzip git build-essential
java -version
```

The package names can vary by Ubuntu release. Do not install a JDK version solely because it is available in the distribution; verify the requirement of the Joern release you intend to run.

## 4. Install Joern separately

The official installer is published by the Joern project. Review the official [installation guide](https://docs.joern.io/installation/) before executing it. A documented interactive installation flow is:

```bash
mkdir -p ~/opt/joern-install
cd ~/opt/joern-install
curl -L \
  https://github.com/joernio/joern/releases/latest/download/joern-install.sh \
  -o joern-install.sh
chmod u+x joern-install.sh
./joern-install.sh --interactive
```

The installer may place launchers under `~/bin`. If that directory is not already in `PATH`, add it to the shell configuration used by your account, then open a new shell or reload the configuration:

```bash
export PATH="$HOME/bin:$PATH"
hash -r
```

For a reproducible research environment, prefer a specific Joern release artifact rather than the `latest` endpoint, record its release tag and checksum, and retain the installation details with the experiment metadata.

## 5. Verify the required executables

The current EvidenceLab capture code relies on these executables:

| Executable | Used for | Required when |
|---|---|---|
| `joern-parse` | Parse source and write `cpg.bin`. | Every capture. |
| `joern-export` | Export GraphML and optionally GraphSON. | Every capture. |
| `joern-slice` | Compute a JSON data-flow slice. | Data-flow capture is enabled. |
| `joern` | Query the Joern version where possible and support manual CPG investigation. | Helpful for diagnostics and query exploration; the capture implementation records a null version if it cannot determine it. |

Run:

```bash
command -v joern
command -v joern-parse
command -v joern-export
command -v joern-slice
joern --help
joern-parse --help
joern-export --help
joern-slice --help
```

Then check from the EvidenceLab virtual environment:

```bash
python -m evidencelab doctor --joern
```

A successful `command -v` check proves only that an executable is discoverable. Run the capture test below to prove that the tools actually operate together on a source file.

## 6. Capture one source file

Choose a small source file first. For example, use one of the checked-in C files under `examples/cwe-121/` that your checkout includes. Inspect the available files before running the command:

```bash
find examples/cwe-121 -type f -name '*.c' | sort | head -20
```

Capture it into a new output directory:

```bash
SOURCE="$(find examples/cwe-121 -type f -name '*.c' | sort | head -1)"
test -n "$SOURCE"
python -m evidencelab capture \
  --source "$SOURCE" \
  --out /tmp/evidencelab-joern-capture \
  --dataflow-timeout 240 \
  --dataflow-slice-depth 8
```

`capture` is destructive to stale generated artifacts **inside the specified output directory**: it deletes old CPG/export/slice outputs before regenerating them. Do not point it at a directory containing unrelated files.

The default capture requests GraphSON and data-flow analysis. `--no-graphson` omits GraphSON. `--no-dataflow` skips the data-flow slice. The source can be a file or a source path accepted by the installed `joern-parse`; begin with a single file when diagnosing an installation.

## 7. Inspect capture artifacts

A successful capture normally contains the following layout (exact exported names are determined by Joern):

```text
/tmp/evidencelab-joern-capture/
  cpg.bin
  graphml/
    export.xml
  graphson/
    export.json           # exact extension/name may vary
  dataflow.json           # present when a slice was emitted
  capture-manifest.json
```

The manifest records:

- EvidenceLab artifact-contract version and EvidenceLab package version;
- source path and SHA-256 digest;
- Joern version when detected;
- paths to the CPG, exports, and data-flow artifact;
- data-flow request settings such as timeout, slice depth, and filters;
- command stdout/stderr and status;
- an analysis-attestation level and capture status.

Inspect the manifest before relying on the graph:

```bash
python -m json.tool /tmp/evidencelab-joern-capture/capture-manifest.json | less
```

A manifest status of `DEGRADED`, a data-flow state such as `TIMEOUT` or `FAILED`, or a missing expected artifact must remain visible downstream. It is not a negative vulnerability result.

## 8. Timeout and best-effort behavior

Data-flow slicing may be expensive. The following controls are available:

- `--dataflow-timeout SECONDS`: bounds the data-flow command; the default is 300 seconds.
- `--dataflow-slice-depth N`: sets Joern's slice depth; the default is 8.
- `--dataflow-file-filter VALUE`: limits the slice by file filter.
- `--dataflow-method-name-filter VALUE`: limits the slice by method-name filter.
- `--best-effort-dataflow`: retain the full-graph capture and write a degraded manifest if data-flow slicing fails or times out instead of treating the capture as fully complete.

Best effort is useful for exploration, not a way to hide missing analysis. A graph without data-flow evidence may not support a data-flow claim. EvidenceLab should preserve that incompleteness and may return `UNKNOWN` or another non-definitive outcome according to the Evidence specification.

## 9. Merge supported exports

EvidenceLab can parse supported GraphML, GraphSON, data-flow-slice JSON, and canonical graph JSON. To merge a full export and the optional data-flow artifact:

```bash
ARGS=(--graph /tmp/evidencelab-joern-capture/graphml/export.xml)
if test -f /tmp/evidencelab-joern-capture/dataflow.json; then
  ARGS+=(--graph /tmp/evidencelab-joern-capture/dataflow.json)
fi
python -m evidencelab merge \
  "${ARGS[@]}" \
  --out /tmp/evidencelab-joern-graph.json \
  --pretty
```

GraphML exports can lose list-valued properties. Retain the original `cpg.bin`, GraphSON, GraphML, data-flow JSON, and manifest even after merging. Treat canonicalization as a derived artifact, not a replacement for the source analyzer exports.

Inspect the merged graph:

```bash
python -m evidencelab inspect \
  --graph /tmp/evidencelab-joern-graph.json \
  --detailed
```

## 10. Run an Evidence scan

When a researcher-authored Evidence Pattern is available, `scan` performs capture, graph merge, matching, and witness replay, then writes a report directory:

```bash
python -m evidencelab scan \
  --source "$SOURCE" \
  --pattern examples/cwe-121/evidence-pattern.json \
  --out /tmp/evidencelab-scan
```

`--pattern` may be repeated to evaluate multiple pattern files. Use `--family-root` when patterns are loaded from a family directory according to the repository's family layout. The default retains the underlying capture artifacts under the output directory; `--no-capture-retention` removes those artifacts after scanning, so avoid that option when collecting research evidence.

Review `scan.json`, `canonical-graph.json`, the capture manifest, each per-pattern result, and witness replay status. Do not report only the top-level status while omitting degradation and provenance context.

## 11. Run the Joern end-to-end test

Once `joern-parse`, `joern-export`, and `joern-slice` are available:

```bash
python -m evidencelab doctor --joern
./scripts/joern_e2e.sh
```

To place outputs somewhere else:

```bash
./scripts/joern_e2e.sh /tmp/evidencelab-joern-e2e
```

The script captures each checked-in C source case, merges the graph exports, and writes an `e2e-report.json`. It uses bounded per-case operations. By default, a best-effort data-flow timeout can produce `PASS_WITH_WARNINGS`; set `EVIDENCELAB_E2E_STRICT=1` to fail the run when those warnings occur. Adjust the per-case ceiling with `EVIDENCELAB_E2E_CASE_TIMEOUT` and data-flow timeout/depth through the environment variables documented in the script.

A test run with `SKIP_JOERN_E2E=1` does not perform this validation. Record whether Joern E2E was run, the Joern release, operating system, JDK version, exact command, report path, and any degraded data-flow cases.

## Supported graph inputs and failure classification

The parser supports GraphML, GraphSON, Joern `DataFlowSlice` JSON, supported reachable-by-flow path JSON, and EvidenceLab canonical graph JSON. For auditability, retain the original CPG and exports. GraphML can lose list-valued properties; a data-flow slice is a partial view, not the entire CPG.

Keep these states distinct: tool missing; parse/CPG generation failed; export failed or produced no file; slice timed out; slice failed; export parsed but lacks facts needed by a claim; complete graph did not match; stored witness failed replay. The first six concern installation, capture, or completeness—not proof that a vulnerability is absent. The capture manifest should make the distinction visible.

## 12. What Joern does not prove for EvidenceLab

A successful Joern parse proves that a particular source input was processed and artifacts were emitted. It does not automatically prove:

- that the chosen data-flow model is complete for the research question;
- that aliasing, wrappers, interprocedural behavior, macros, or library semantics are modeled as required;
- that Evidence claims are sufficient or sound;
- that the benchmark labels are correct;
- that a pattern generalizes to unseen repositories or projects.

Those are research questions. Record assumptions, counterexamples, analyzer limitations, and external evaluation separately.
