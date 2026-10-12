# EvidenceLab 1.0.0

**A researcher-driven framework for defining, executing, and evaluating vulnerability Evidence.**

EvidenceLab turns a security hypothesis into a machine-executable definition with explicit claims, coherent witnesses, counter-evidence, uncertainty, provenance, and reviewable results. The researcher defines what counts as evidence; analyzers provide observations and EvidenceLab checks the definition against supported graph inputs.

## Start here

For a source checkout on Linux, install the runtime package in a virtual environment:

```bash
git clone https://github.com/gashasbi/evidencelab.git
cd evidencelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m evidencelab --version
```

Then follow the [Quickstart](docs/quickstart.md) to run the bundled vulnerable and safe graph examples. These examples use prebuilt graphs and do **not** require Joern.

## What EvidenceLab does

- validates and compiles researcher-authored Evidence Specification Language (ELS);
- evaluates required claims against supported graph artifacts and requires coherent witness bindings;
- records counter-evidence and keeps `NO_MATCH` distinct from `UNKNOWN` when analysis is incomplete;
- maps external dataset records into a canonical experimental-material format;
- supports evaluation, provenance, witness replay, benchmark controls, and reproducibility workflows.

EvidenceLab is not a replacement for Joern or another analyzer. The Python package does not install Joern. Live source capture requires the relevant external Joern executables; see [Installation](docs/installation.md) and [Joern integration](docs/joern-integration.md).

## Interpret results carefully

`MATCH` means a coherent witness satisfied the required Evidence under the declared policies. `NO_MATCH` means no admissible witness was established on an input complete enough for that decision. `PARTIAL` and `UNKNOWN` must not be reported as definitive negatives. A valid ELS file, successful command, or passing unit test does not by itself establish scientific validity or generalization.

The checked-in CWE-120/CWE-121 artifacts are reference examples. They demonstrate contracts and workflows; they are not an independently validated benchmark and do not establish precision, recall, or generalization across real-world code.

## Documentation by task

| You want to… | Read |
|---|---|
| Install and verify the package | [Installation](docs/installation.md) |
| Run the first example | [Quickstart](docs/quickstart.md) |
| Diagnose an error | [Troubleshooting](docs/troubleshooting.md) |
| Write or review ELS | [ELS reference](docs/evidence-dsl.md) and [Evidence model](docs/evidence-model.md) |
| Analyze real source with Joern | [Joern integration](docs/joern-integration.md) |
| Import an external dataset | [Dataset integration](docs/dataset-integration.md) |
| Design a defensible evaluation | [Research methodology](docs/research-methodology.md) and [Benchmark design](docs/benchmark-design.md) |
| Find a command or package API entry point | [CLI reference](docs/cli-reference.md) |

The [documentation index](docs/README.md) lists the remaining specialist references. You do not need to read every page to use the basic workflow.

## Development checks

For tests and release checks, install the development extra:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The release smoke also runs the live Joern E2E unless skipped. If Joern is unavailable, `SKIP_JOERN_E2E=1 ./scripts/release_test.sh` checks the non-Joern paths only; it does not verify live analyzer integration.

## Scope and safety

Treat source code, dataset files, manifests, and analyzer exports as untrusted input. EvidenceLab is not a sandbox for hostile code; isolate analyzers, apply resource limits, and retain analysis failures as explicit failure or completeness states. See the [Security model](docs/security-model.md).

Package version `1.0.0` and artifact schema version `1.0` are different identifiers. Citation metadata is in [`CITATION.cff`](CITATION.cff); the project is licensed under [MIT](LICENSE).
