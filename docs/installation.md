# Installation

EvidenceLab's Python package and its external analyzer integrations are separate. You can run the bundled graph examples without Joern. You need Joern only for live source capture and workflows that invoke it.

## Requirements

- Python 3.11 or newer.
- `pip` and `venv` for an isolated environment.
- Network access to the configured Python package index, or an approved mirror/wheelhouse containing build and runtime dependencies.
- Joern and its own host prerequisites only for live analyzer workflows; see [Joern integration](joern-integration.md).

`jsonschema` is installed as a runtime dependency. `pytest` is included in the `dev` extra, not in a runtime-only install. Optional extras are `tef` (YAML support) and `realdata` (PyArrow workflows).

## Install from a checkout

```bash
git clone https://github.com/gashasbi/evidencelab.git
cd evidencelab
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Run these commands from the repository root (the directory containing `pyproject.toml` and `evidencelab/`). On Debian/Ubuntu, if creating the environment fails because `venv` is missing, install the OS package that provides it, commonly `python3-venv`, then retry. Do not use `sudo pip` or install into the system interpreter.

For contribution and test work, install the development extra instead:

```bash
python -m pip install -e ".[dev]"
```

To enable optional workflows, install only the extras they need:

```bash
python -m pip install -e ".[dev,tef]"
# Or use .[realdata] for workflows that require PyArrow.
```

An editable install is convenient for a source checkout. A release/package verification should also build a wheel and test it in a separate clean environment; see below.

## Verify the installation

```bash
python -m evidencelab --version
python -m evidencelab --help
python -m evidencelab doctor
```

Expected version output for this source release:

```text
evidencelab 1.0.0
```

`doctor` reports detectable capabilities; it does not install missing software. Check `python -m evidencelab doctor --joern` only when preparing a Joern workflow. Missing Joern does not prevent the bundled canonical-graph Quickstart.

## Run tests (contributors)

After installing `.[dev]`:

```bash
python -m pytest -q
```

The isolated regression runner executes each test file in a separate process:

```bash
python scripts/run_isolated_tests.py --timeout 180
```

The release smoke invokes Joern E2E unless explicitly skipped:

```bash
./scripts/release_test.sh
# Without live Joern; this does not validate the analyzer integration:
SKIP_JOERN_E2E=1 ./scripts/release_test.sh
```

## Build and test a wheel (maintainers)

```bash
python -m pip install build
python -m build --outdir /tmp/evidencelab-dist
```

Installing from the wheel in a new virtual environment is a stronger package test than an editable install. A wheel build alone does not test the CLI or Joern integration. The [Troubleshooting](troubleshooting.md) page covers missing build dependencies, offline installs, and common execution failures.

## Offline and platform notes

A fresh install may need to download `setuptools>=68` and `jsonschema` (plus `pytest` for `.[dev]`). In a restricted environment, use the site's approved package mirror or wheelhouse and preserve pip's complete error output. A network failure by itself does not prove a source defect.

Linux is the primary documented path. Helper and release scripts use Bash; Windows users should use a Bash-capable environment such as WSL and verify Joern separately. Joern's JDK requirement depends on the selected release; consult that release's official installation instructions.
