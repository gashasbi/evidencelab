# Troubleshooting

First preserve the full command, exit code, Python version, and unabridged error output. Identify which layer failed before changing code: package installation, CLI invocation, graph parsing, analyzer capture, or research/evaluation gates.

## The CLI cannot be imported or the version command fails

```bash
which python
python --version
python -m pip show evidencelab
python -m evidencelab --version
```

Activate the intended `.venv` and run from the project root. If `pip show` points to a different environment, install the package into the active interpreter with `python -m pip install -e .`.

## `No module named pytest`

Runtime installation intentionally excludes the test runner. From the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest --version
```

Do not report tests as failed before the test runner starts, and do not report a pass if the tests never ran.

## pip fails while installing build or runtime dependencies

Check the interpreter, pip configuration, configured package index, and full resolver message:

```bash
python --version
python -m pip --version
python -m pip config list
```

The build backend requires `setuptools>=68`; runtime installation requires `jsonschema>=4.21,<5`. Network restrictions, an unavailable mirror, or missing wheels can block installation without indicating a source-code defect. Use an approved package mirror/wheelhouse where required; avoid `sudo pip`.

## The release script stops before Joern E2E

The full release smoke exercises external Joern unless skipped. To run the Python and bundled reference checks only:

```bash
SKIP_JOERN_E2E=1 ./scripts/release_test.sh
```

This does **not** test live analyzer integration. To see the exact failed regression, run the named test file directly with `python -m pytest -q tests/test_file.py`.

## `doctor --joern` reports missing executables

```bash
command -v joern-parse
command -v joern-export
command -v joern-slice
printf '%s\n' "$PATH"
```

EvidenceLab does not install Joern. Follow [Joern integration](joern-integration.md), reload the shell after changing `PATH`, and run `python -m evidencelab doctor --joern` again. Finding a command in `PATH` proves discoverability, not that capture succeeds.

## Joern parse succeeds but export or data-flow fails

Preserve the capture directory and `capture-manifest.json`. Check that `cpg.bin` exists, inspect the installed command's `--help`, and confirm the output directory is writable. Use `--best-effort-dataflow` only for exploratory runs that can accept a degraded manifest. `TIMEOUT`, `FAILED`, or `DEGRADED` must remain visible; a missing slice is not proof that no flow exists.

GraphML may not preserve every list-valued property. Retain GraphSON and the original CPG when those properties matter, and compare exports before treating them as equivalent.

## Dataset mapping rejects a path

Mapping artifact paths are resolved relative to `source_root`. Absolute paths and paths escaping that root are rejected. Move the source into the declared root or change the mapping deliberately; do not weaken path checks to force a pass.

The validation digest and materialization file hash identify different things: `mapping_digest` hashes canonicalized parsed JSON, while `mapping_sha256` hashes the mapping file's exact bytes. They need not be equal.

## Result is `UNKNOWN`, `PARTIAL`, or an unexpected `NO_MATCH`

Check, in order:

1. Was the expected graph or capture artifact created and parsed?
2. Did the capture manifest report complete or degraded analysis?
3. Were candidate, path-depth, or combination limits reached?
4. Do selectors find the intended nodes, and do edges use the right direction/type?
5. Do required claims refer to one coherent witness?
6. Is counter-evidence blocking the witness?
7. Is a required property unresolved or unsupported in the graph?

Use `inspect`, `evidence validate`, `audit`, and witness replay as applicable. Do not weaken required claims until you understand the failed proof obligation.

## Schema or research gate fails

Validate against the schema for the correct artifact type. Package version `1.0.0` and artifact schema version `1.0` are different. For research gates, read the report and identify whether the failure concerns structure, labels, source identity, case coverage, leakage, provenance, witness replay, or profile thresholds. Do not duplicate cases, relabel unknowns, or relax a profile only to obtain a pass.

## Report a reproducible defect

Include the EvidenceLab/Python/OS versions, exact command and exit code, minimal input or fixture name, full output, related manifest/report, expected and actual behavior, and whether it reproduces in a clean virtual environment. Do not attach secrets, restricted datasets, or private source without authorization.
