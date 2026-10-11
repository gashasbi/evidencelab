# CWE-120 Evidence Research Pack (EvidenceLab)

This is a reference research package, not a claim that CWE-120 is solved. It demonstrates a disciplined method for converting a broad CWE into multiple executable Evidence Families.

## Families

1. **fixed-extent-overflow** — proves a fixed write extent exceeds proven byte capacity.
2. **symbolic-range-overflow** — proves the complete possible extent range exceeds capacity; overlapping ranges are UNKNOWN.
3. **unbounded-string-copy** — proves an unchecked/unbounded string transfer to a finite-capacity target; does not infer exact overflow magnitude.
4. **unbounded-format-output** — proves `sprintf`/`vsprintf`-style unbounded formatted output to finite capacity.
5. **unbounded-input** — proves unbounded `gets`/`scanf`-style destination input.
6. **allocation-capacity-overflow** — fixed copy exceeds a proven heap allocation size.

## Public validation

```bash
python -m evidencelab research-check \
  --root examples/cwe-120 \
  --profile profiles/research-grade-c-cpp-joern.json \
  --enforce-gates
```

## Real Joern validation

```bash
./scripts/cwe120_research_e2e.sh
```

The real-Joern script keeps per-case logs and applies bounded data-flow slicing. The evaluator should still run a separate hidden benchmark outside the researcher workspace.

## Interpretation

`MATCH` means the Evidence Family is proven, not that exploitability is proven. `UNKNOWN` is a first-class outcome.
