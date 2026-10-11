# Installation and environment setup

This guide installs EvidenceLab 1.0.0 from a source checkout or release archive and distinguishes runtime dependencies from development dependencies and external analyzers.

## Requirements

| Component | Requirement | Purpose |
|---|---|---|
| Python | 3.11 or newer | EvidenceLab runtime and CLI. |
| pip and venv | Current versions recommended | Isolated package installation. |
| `jsonschema` | Installed as a declared runtime dependency | Validation of JSON artifacts against JSON Schema. |
| `pytest` | Development extra only | Unit, regression, and release testing. |
| Joern CLI | Optional external dependency; required for live Joern capture and E2E | Code Property Graph construction, export, and data-flow slicing. |
| JDK | Follow the requirement for the selected Joern release; the current Joern repository README specifies JDK 21 | Runs Joern. |
| C/C++ compiler toolchain | Recommended for C/C++ analysis and system-header discovery | Helps Joern process native-code projects and headers. |

The Python package does not install Joern. See [Joern integration](joern-integration.md) for the external tool installation path.

## 1. Extract the source release

For a downloaded release archive:

```bash
mkdir -p ~/src/evidencelab-1.0.0
unzip evidencelab-1.0.0.zip -d ~/src/evidencelab-1.0.0
cd ~/src/evidencelab-1.0.0
```

If the archive contains a top-level `evidencelab-1.0.0/` directory, change into that inner directory. The repository root is the directory containing `pyproject.toml`, `README.md`, `evidencelab/`, `schemas/`, `docs/`, and `scripts/`.

## 2. Create a virtual environment

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

If `venv` is unavailable on Debian or Ubuntu, install the distribution package that provides it (commonly `python3-venv`) and retry. Do not use `sudo pip` and do not install project packages into the system interpreter.

## 3. Install the package

### Runtime-only environment

```bash
python -m pip install -e .
```

This installs the project and declared runtime dependencies. It is sufficient for normal CLI use but does not install `pytest`.

### Development and test environment (recommended for a source checkout)

```bash
python -m pip install -e ".[dev]"
```

The `dev` extra adds the test runner. This is the recommended installation for contributors and anyone running `scripts/release_test.sh`. The equivalent development requirements are listed in `requirements-dev.txt`, but the editable install with `.[dev]` also installs EvidenceLab itself.

Optional extras declared by the package are:

- `.[tef]`: YAML support for TEF bridge operations.
- `.[realdata]`: PyArrow support for workflows that need it.

Install only the extras needed for the selected workflow, for example:

```bash
python -m pip install -e ".[dev,tef]"
```

## 4. Verify installation

```bash
python -m evidencelab --version
python -m evidencelab --help
python -m evidencelab doctor
python -m pytest --version
```

Expected version output:

```text
evidencelab 1.0.0
```

`doctor` reports environment capabilities. Use `python -m evidencelab doctor --joern` when you want the Joern-specific checks; Joern checks do not install or repair Joern.

## 5. Validate the bundled artifacts

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els

python -m evidencelab dataset-model-validate \
  --model examples/dataset-model/simple-vuln-dataset.json

python -m evidencelab research-audit \
  --root examples/cwe-121 \
  --out /tmp/evidencelab-reference-audit.json
```

Inspect the resulting JSON report before using the material as a research baseline. These commands validate the bundled reference workflow, not a claim of external generalization.

## 6. Run tests

Quick unit and regression run:

```bash
python -m pytest -q
```

Isolated test execution, which launches the test files in separate processes:

```bash
python scripts/run_isolated_tests.py --timeout 180
```

Full release smoke:

```bash
./scripts/release_test.sh
```

The full release script runs the test suite, reference research audit, development evaluation, ELS compilation/execution, dataset-model import, and—unless skipped—the Joern E2E. To run the non-Joern checks only:

```bash
SKIP_JOERN_E2E=1 ./scripts/release_test.sh
```

This skip flag does not verify Joern integration. Run the live workflow separately on a machine with the required Joern executables in `PATH`.

## Offline or restricted-network environments

`pip install -e .` may need to download build-system requirements and runtime dependencies. `pip install -e ".[dev]"` also needs the test dependencies if they are not cached. If the environment has no network access:

1. Use an approved wheelhouse or package mirror for the dependencies listed by the project.
2. Install the required dependencies from that wheelhouse into the virtual environment.
3. Re-run the editable installation using the site's approved offline pip procedure.
4. Verify each dependency and the CLI independently before running tests.

An install blocked by missing network access is not proof of a source defect. Conversely, do not report a test suite as passing if the test runner was unavailable and the tests never executed.

## Build a wheel

```bash
python -m pip wheel --no-deps . --wheel-dir dist
```

The wheel build validates packaging metadata but does not install the wheel into a clean interpreter or test an external analyzer. For distribution testing, create a separate virtual environment, install the wheel plus runtime dependencies, and run the verification commands there.

## Platform notes

The Python CLI is implemented in Python, but the repository's helper scripts use Bash and the Joern integration uses external command-line executables. Linux is the primary documented path. On Windows, use a Bash-capable environment such as WSL for the documented helper scripts, and verify Joern's platform-specific installation separately.
