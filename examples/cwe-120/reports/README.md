# CWE-120 evaluation reports

Evaluation reports are generated artifacts and are intentionally not committed to the release package.
The source corpus, evidence families, patterns, graphs, and benchmark manifests are the reproducible inputs.

Generate fresh reports with the installed EvidenceLab version:

```bash
python -m evidencelab evaluate-benchmark \
  --benchmark examples/cwe-120/families/fixed-extent-overflow/benchmark.json \
  --pattern examples/cwe-120/families/fixed-extent-overflow/pattern.json \
  --out examples/cwe-120/reports/evaluations/fixed-extent-overflow
```

For a research-grade result, run the family through `research-check` or `research-evaluate`
with the appropriate publication/evaluator profile. A generated public report is not a substitute
for an evaluator-controlled hidden benchmark.

The release deliberately does not ship reports containing machine-local absolute paths or stale
framework-version metadata.
