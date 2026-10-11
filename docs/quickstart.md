# Quickstart

This walkthrough verifies the installation, validates a researcher-authored Evidence definition, executes it against a canonical graph, and materializes a small external-material mapping. It does not require a live Joern installation because the graph is already bundled in canonical form.

## Prerequisites

From the repository root, activate the virtual environment and install the development extra if you intend to run the complete test suite:

```bash
source .venv/bin/activate
python -m evidencelab --version
```

## 1. Inspect the environment

```bash
python -m evidencelab doctor
```

For live Joern checks, use:

```bash
python -m evidencelab doctor --joern
```

## 2. Validate an ELS specification

```bash
python -m evidencelab evidence validate \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els
```

This checks the ELS source against the implemented grammar and semantic constraints. Passing validation does not prove that the Evidence is scientifically sufficient; that requires test material and evaluation.

## 3. Compile the specification

```bash
python -m evidencelab evidence compile \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --out /tmp/evidencelab-fixed-write-pattern.json
```

The output is an Evidence Pattern in the public schema contract. Keep the ELS source and compiled Pattern together so changes can be reviewed and reproduced.

## 4. Execute against a canonical graph

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/vulnerable.json \
  --out /tmp/evidencelab-fixed-write-result.json
```

Inspect the JSON result. The example is expected to produce a positive match because it is a deliberately constructed reference graph. Do not interpret this one-case result as benchmark precision or recall.

Try the safe reference graph as a contrast:

```bash
python -m evidencelab evidence run \
  --spec examples/evidence-dsl/cwe121-fixed-write-research-grade.els \
  --graph examples/cwe-121/graphs/safe.json \
  --out /tmp/evidencelab-fixed-write-safe-result.json
```

The final outcome depends on the precise Evidence claims, available graph facts, and policy; inspect the report rather than assuming that a missing positive witness always means `NO_MATCH`.

## 5. Validate and preview an experimental-material mapping

```bash
python -m evidencelab dataset-model-validate \
  --model examples/dataset-model/simple-vuln-dataset.json

python -m evidencelab dataset-model-preview \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --limit 3
```

The preview inspects materialization without running a program analyzer.

## 6. Materialize the canonical manifest

```bash
python -m evidencelab dataset-model-import \
  --model examples/dataset-model/simple-vuln-dataset.json \
  --out /tmp/evidencelab-example-material.json
```

The bundled example contains three cases with the declared truth states `BAD`, `GOOD`, and `UNKNOWN`. These truth labels remain dataset-side declarations; they do not force Evidence matcher outcomes.

## 7. Run the regression suite

After installing the development extra:

```bash
python -m pytest -q
```

For release verification, use `./scripts/release_test.sh`. If you skip the Joern E2E with `SKIP_JOERN_E2E=1`, record that the external analyzer path was not exercised.

## Next steps

- Learn the Evidence semantics in [Evidence model](evidence-model.md).
- Author or change a definition using [ELS](evidence-dsl.md).
- Capture real source with [Joern integration](joern-integration.md).
- Design an independent benchmark with [Benchmark design](benchmark-design.md) and [Research methodology](research-methodology.md).
