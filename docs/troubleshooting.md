# Troubleshooting

Before changing code, preserve the full command, exit code, Python version, and complete error output. Identify which layer failed: installation, CLI invocation, graph parsing, analyzer capture, or research/evaluation gates.

## The CLI cannot be imported

```bash
which python
python --version
python -m pip show evidencelab
python -m evidencelab --version
```

Activate the intended virtual environment and run from the repository root. If `pip show` points to another environment, install into the active interpreter with `python -m pip install -e .`.

## `No module named pytest`

The runtime install intentionally excludes the test runner:

```bash
python -m pip install -e ".[dev]"
python -m pytest --version
```

## Installation fails

Check the interpreter, pip configuration, package index, and full resolver error:

```bash
python --version
python -m pip --version
python -m pip config list

Before sharing this output, inspect and redact credentials, tokens, private repository URLs, usernames, or other sensitive configuration values.
```

The build backend requires `setuptools>=68`; runtime installation requires `jsonschema>=4.21,<5`. Network restrictions or missing wheels can block installation without indicating a source-code defect. Use an approved mirror/wheelhouse when needed and avoid `sudo pip`.

## Joern executables are missing

```bash
command -v joern-parse
command -v joern-export
command -v joern-slice
printf '%s\n' "$PATH"
python -m evidencelab doctor --joern
```

EvidenceLab does not install Joern. Follow [Joern integration](joern-integration.md), reload the shell after changing `PATH`, and retry. Finding an executable on `PATH` proves only that it is discoverable.

## Joern capture fails or is degraded

Preserve the capture directory and `capture-manifest.json`. Check that the CPG exists, inspect each installed command's `--help`, and confirm that the output directory is writable. Use best-effort data-flow options only when the workflow can tolerate degraded output.

A timeout, failed export, or missing data-flow slice is not proof that a flow does not exist. Keep `TIMEOUT`, `FAILED`, or degraded states visible.

## Dataset mapping rejects a path

Artifact paths are resolved relative to the declared source root. Absolute paths and paths escaping that root are rejected by design. Move the file under the declared root or correct the mapping deliberately; do not weaken path restrictions just to obtain a pass.

A digest of canonicalized mapping content and a hash of the original mapping file bytes may differ because they identify different representations.

## Result is `UNKNOWN`, `PARTIAL`, or an unexpected `NO_MATCH`

Check:

1. Was the intended graph or capture artifact created and parsed?
2. What capture status and completeness metadata were recorded?
3. Were candidate, path-depth, or combination limits reached?
4. Do selectors identify the intended nodes and edges?
5. Do required claims refer to one coherent witness?
6. Is counter-evidence blocking the witness?
7. Is a required property unresolved or unsupported by the input?

Use `inspect`, `evidence validate`, `audit`, and witness replay as appropriate. Do not weaken required claims until the failed proof obligation is understood.

## A research gate fails

Read the report and identify whether the failure concerns structure, labels, case coverage, provenance, source identity, leakage, witness replay, or profile thresholds. Do not duplicate cases, relabel unknowns, or relax a profile only to make it pass.

## Report a reproducible defect

Include EvidenceLab/Python/OS versions, exact command and exit code, minimal input or fixture name, full output, related manifest/report, expected versus actual behavior, and whether it reproduces in a clean virtual environment. Do not attach secrets, restricted datasets, or private source without authorization.
