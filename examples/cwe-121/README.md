# CWE-121 Evidence Research Package

This is EvidenceLab 1.0.0's reference research package for two deliberately bounded CWE-121 evidence families in C/C++:

- `fixed-write`: a proven fixed byte extent exceeds the byte capacity of one automatic local array;
- `unbounded-copy`: an unbounded string-copy-like operation targets one automatic local array.

The package contains 87 canonical graph benchmark cases (47 fixed-write and 40 unbounded-copy), a source-level C/C++ smoke corpus, and explicit uncertainty/negative cases. The graph fixtures are development/reference material; they are not 87 independent real-world programs and do not establish publication-grade precision, recall, or generalization.

## Review the coverage boundary

Read [Coverage and acceptance matrix](coverage-matrix.md) before interpreting results. Indexed loop writes, arbitrary pointer arithmetic, formatted output/input, multi-file real-source analysis, and general path-sensitive range analysis are not claimed by these two families.

## Test and evaluate

```bash
python -m pytest -q tests/test_cwe121_source_corpus.py
python -m evidencelab research-check --root examples/cwe-121 \
  --profile profiles/research-grade-c-cpp-joern.json --enforce-gates
```

For live source capture, install the external Joern CLI tools (`joern-parse`, `joern-export`, `joern-slice`) and run:

```bash
./scripts/joern_e2e.sh /tmp/evidencelab-cwe121-e2e
```

The E2E script captures and merges each C/C++ source and then evaluates the resulting graphs against both reference patterns. Review `cwe121-evaluation-report.json`; an incomplete graph is not a safe negative. Use `EVIDENCELAB_E2E_STRICT=1` to fail on expectation mismatches and inconclusive/out-of-scope cases.

A `MATCH` is an Evidence-family match, not proof of exploitability or physical stack placement. Automatic storage duration is not a machine-level proof that an object physically resides in a stack frame. External dataset labels, source-level expectations, analyzer observations, and Evidence outcomes remain separate.
