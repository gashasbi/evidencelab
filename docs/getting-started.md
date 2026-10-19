# Getting started

This guide installs EvidenceLab and runs a bundled example using prebuilt graph artifacts. It does not invoke Joern or analyze source code.

## Requirements

- Python 3.11 or newer.
- `pip` and `venv`.
- Network access to a package index or an approved mirror/wheelhouse for dependencies.
- Joern only if you later run live source capture.

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

If Ubuntu/Debian cannot create the virtual environment because `venv` is missing, install the OS package that provides it (commonly `python3-venv`) and retry. Avoid `sudo pip`; install into the active virtual environment.

Verify the installation:

```bash
python -m evidencelab --version
python -m evidencelab --help
python -m evidencelab doctor
```

`doctor` reports detected capabilities; it does not install missing dependencies or guarantee that an analyzer run will succeed.

## Validate the bundled definition

Run from the repository root:

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els
```

This validates the definition's contract. It does not prove that the definition is sufficient for every real-world program.

## Run the vulnerable graph

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/vulnerable.json \
  --out /tmp/evidencelab-vulnerable.json
```

Then inspect `/tmp/evidencelab-vulnerable.json`, especially `status`, evidence trace, warnings, and completeness fields.

## Run the safe graph

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/safe.json \
  --out /tmp/evidencelab-safe.json
```

**Exit-code note:** in the current CLI behavior, `evidence run` returns exit code `0` for `MATCH` and `1` for other outcomes, including an expected `NO_MATCH` on a safe fixture. A nonzero exit code therefore needs to be interpreted alongside the JSON report; it is not automatically an operational crash.

## Install development or optional dependencies

For tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Optional extras are separate from the runtime install:

- `.[tef]` installs YAML support for TEF workflows.
- `.[realdata]` installs PyArrow for workflows that need it.

## Next steps

- [Evidence and ELS reference](evidence-reference.md)
- [CLI reference](cli-reference.md)
- [Joern integration](joern-integration.md) for live source capture
- [Troubleshooting](troubleshooting.md) for common setup and runtime failures
