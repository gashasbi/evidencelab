# Troubleshooting

This page covers common installation and execution problems in EvidenceLab 1.0.0. Start by preserving the complete error output; do not edit project code before identifying which layer failed.

## `python -m evidencelab --version` fails

Confirm that the virtual environment is active and the package is installed in that interpreter:

```bash
which python
python --version
python -m pip show evidencelab
python -m evidencelab --version
```

The expected project version is `1.0.0`. If `python -m pip show evidencelab` points to a different interpreter or environment, activate the intended `.venv` and reinstall from the repository root.

## `No module named pytest`

This means the test runner is not installed in the active interpreter. `python -m pip install -e .` installs runtime dependencies, not development dependencies. From the project root and with `.venv` active, run:

```bash
python -m pip install -e ".[dev]"
python -m pytest --version
```

Then retry the test command. Do not mark the suite failed before the test runner has started, and do not report it as passing when it has not run.

## `pip install -e .` fails while installing build dependencies

Check Python version, pip version, network policy, configured package index, and availability of the build-system requirement `setuptools>=68`:

```bash
python --version
python -m pip --version
python -m pip config list
python -m pip install "setuptools>=68"
```

In an offline environment, use an approved internal index or wheelhouse containing the required build/runtime/test dependencies. Do not assume that a build failure caused by network access is a source defect. Preserve the full pip output for diagnosis.

## `release_test.sh` stops before the first test

The script prints a numbered test name and then starts that test in a subprocess. If the output shows `No module named pytest`, install `.[dev]`. Otherwise, run the reported test file directly to get the focused traceback:

```bash
python -m pytest -q tests/test_capture_controls.py
```

To run the full suite without invoking external Joern tools:

```bash
SKIP_JOERN_E2E=1 ./scripts/release_test.sh
```

This validates the local Python/reference workflows but intentionally skips the live Joern end-to-end test.

## `doctor --joern` reports missing executables

Check every executable that EvidenceLab calls:

```bash
command -v joern
command -v joern-parse
command -v joern-export
command -v joern-slice
printf '%s\n' "$PATH"
```

Joern is installed separately. Follow the [official Joern installation guide](https://docs.joern.io/installation/) and the [EvidenceLab Joern integration guide](joern-integration.md). After updating `PATH`, start a new shell and run `hash -r`.

## Joern parses but export fails

Save the command output and the complete capture directory. Confirm that `joern-parse` created `cpg.bin`, that the selected Joern release supports the requested export options, and that output directories are writable. Inspect the installed command's `--help`; do not rely on flags from a different Joern release.

## `joern-slice` times out or has no data-flow output

Increase `--dataflow-timeout`, reduce `--dataflow-slice-depth`, or narrow the file/method filters while exploring. Use `--best-effort-dataflow` only when a degraded result is acceptable for exploration. Inspect `capture-manifest.json` and preserve any `TIMEOUT`, `FAILED`, or `DEGRADED` state. A missing slice is not proof that the source has no data flow.

## GraphML and GraphSON results differ

GraphML can lose list-valued properties in the current Joern exporter. Keep both exports and the original `cpg.bin`; compare property values and parser metadata. Use GraphSON when the values lost by GraphML are material to the Evidence definition. Do not merge conflicting properties without inspecting which source is authoritative.

## `schema-check` or `schema_version` fails

EvidenceLab 1.0.0 uses public artifact schema version `1.0`. The package version `1.0.0` is a separate value. Validate with the schema that corresponds to the intended artifact type, not an unrelated schema file:

```bash
python -m evidencelab schema-check \
  --input path/to/artifact.json \
  --schema schemas/evidence-pattern.schema.json
```

Confirm the target schema filename exists in the checked-out release before copying a command. For imported Evidence Patterns, `migrate-pattern` can normalize a supported external representation, but migration requires researcher review and fresh semantic validation.

## Dataset mapping paths are rejected

Paths to input records and artifacts are resolved relative to `source_root`. Absolute artifact paths and path traversal outside the root are prohibited. Move the source artifact under the declared root or adjust the mapping deliberately, then rerun validation and preview. Do not disable the path checks to make an experiment proceed.

## Unexpected `UNKNOWN`, `PARTIAL`, or non-match

Inspect, in order:

1. whether the expected graph artifact was captured and parsed;
2. whether the capture manifest reports complete or degraded data-flow analysis;
3. whether candidate search hit a cap or path depth bound;
4. whether slot selectors actually select the expected nodes;
5. whether claim relations use the correct direction and canonical relation;
6. whether derived properties exist and are traceable;
7. whether all claims refer to a coherent witness;
8. whether counter-evidence blocks the witness;
9. whether the expected result assumes information missing from the graph.

Run `evidence validate`, `audit`, `inspect`, and witness replay as appropriate. Do not weaken a required claim until you understand why the current proof obligation fails.

## Research gate fails

Read the full report and identify whether the failure concerns structure, sample counts, independent repositories/projects, missing labels/dimensions, metric thresholds, split leakage, provenance, or hidden validation. The development profile is not interchangeable with a publication/submission profile. Do not satisfy a gate by duplicating cases, relabeling unknown cases, or marking a local set as evaluator-controlled.

## Report a reproducible defect

Include:

- EvidenceLab version and Python version;
- operating system and Joern/JDK versions if relevant;
- exact command and return code;
- minimized input or a clear reference to the shipped fixture;
- complete error output and relevant manifest/report;
- whether the issue reproduces on a clean virtual environment;
- expected versus actual behavior.

Do not attach secrets, restricted corpora, or private source code without authorization.
