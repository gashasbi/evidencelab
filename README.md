# EvidenceLab 1.0.0

**A researcher-driven framework for defining, evaluating, and auditing vulnerability evidence.**

EvidenceLab makes a researcher's evidence definition executable over supported graph artifacts. It reports the claims and witnesses that support a result, the counter-evidence that qualifies it, and where the available analysis remains incomplete. It also helps researchers prepare experimental material and check whether benchmark and evaluation artifacts are traceable and reproducible.

EvidenceLab is not itself a source-code analyzer. An analyzer such as Joern produces analysis artifacts; EvidenceLab evaluates researcher-authored definitions against the information those artifacts contain. The analyzer's output, a dataset's label, and EvidenceLab's result are separate kinds of information.

## What it is for

- Define and validate evidence rules with the Evidence Specification Language (ELS).
- Evaluate rules against supported graph inputs and inspect coherent witnesses and counter-evidence.
- Preserve uncertainty when the evidence is incomplete, ambiguous, or insufficient for a definitive decision.
- Support dataset import, benchmark quality checks, provenance, splits and leakage audits, witness replay, and reproducibility records.

A typical run validates an ELS definition, evaluates it against a supported graph, and reviews the result and its uncertainty. Research-level conclusions also require separate checks of dataset identity, label authority, independence, leakage, and reproducibility.

## Quick start

### Requirements

- Python 3.11 or newer.
- `pip` and Python's `venv` module.
- Joern is **not** required for the bundled prebuilt-graph example. It is required only for workflows that invoke live source analysis through Joern.

### Install from source

```bash
git clone https://github.com/gashasbi/evidencelab.git
cd evidencelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m evidencelab --version
python -m evidencelab --help
```

EvidenceLab's package version and the versions of its data formats are separate identifiers. Use `python -m evidencelab --version` to identify an installed package, and consult the relevant schema or artifact metadata when compatibility matters. Do not infer a data-format version from the package version.

### Run a reference example

Validate the bundled ELS definition:

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els
```

Run it against a bundled vulnerable graph:

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/vulnerable.json \
  --out /tmp/evidencelab-vulnerable.json
```

Inspect the JSON report's `status`, trace, warnings, and completeness fields. For a full walkthrough—including the safe reference graph and exit-code behavior—see [Getting started](docs/getting-started.md).

## Understand the result before using it

| Outcome | Practical interpretation |
|---|---|
| `MATCH` | A coherent witness satisfied the required evidence under the definition's policies. |
| `NO_MATCH` | No admissible witness was established on input complete and trustworthy enough to support that negative decision. |
| `PARTIAL` | The analysis or proof is incomplete; do not treat it as a definitive positive or negative. |
| `UNKNOWN` | Available information is insufficient to decide safely. |

A missing edge, timeout, unresolved property, failed export, or truncated search must not be treated as proof that a weakness is absent. The outcome depends on the definition, input format, and completeness information available.

## Documentation

- [Getting started: install and run the first example](docs/getting-started.md)
- [Architecture and data flow](docs/architecture.md)
- [Evidence and ELS reference](docs/evidence-reference.md)
- [Command-line reference](docs/cli-reference.md)
- [Joern integration](docs/joern-integration.md)
- [Dataset integration](docs/dataset-integration.md)
- [Research methodology and benchmark design](docs/research-methodology.md)
- [Reproducibility and witness replay](docs/reproducibility.md)
- [Security model](docs/security-model.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development and tests

To install the development dependencies and run the project's tests from a source checkout:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Where available in the checkout, the isolated test runner executes test files in separate processes:

```bash
python scripts/run_isolated_tests.py --timeout 180
```

Some integration checks may invoke a live Joern installation. If an integration test offers an explicit skip option, skipping it means that external integration was not verified; it does not establish that live Joern behavior works.

## Scope and limitations

- EvidenceLab evaluates a definition against observations in supported artifacts. It cannot recover facts an analyzer did not emit.
- A schema-valid definition is not automatically a sound research hypothesis.
- Passing tests or configured research gates demonstrates only the checks those tests and gates cover.
- Bundled CWE-120/CWE-121 examples are reference fixtures and workflows, not independent real-world validation. They do not by themselves establish general precision, recall, or external validity.
- Dataset labels, analyzer observations, derived facts, evidence claims, witnesses, and final outcomes are different things and should be recorded separately.

## Security

Treat source code, archives, graph exports, manifests, and analyzer outputs as untrusted input. EvidenceLab is not a sandbox for hostile code. Isolate external analyzers, restrict resources and credentials, and verify that you have redistribution rights before bundling datasets.

The project is licensed under MIT. Citation metadata is provided in `CITATION.cff`.
