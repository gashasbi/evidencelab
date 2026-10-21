# Research methodology and benchmark design

EvidenceLab can make an evidence definition executable and research artifacts auditable. It cannot choose the research semantics or establish external validity on its own. Treat a benchmark as an argument about a clearly stated research question—not just a collection of labeled files or graph fixtures.

## 1. State a falsifiable scope

Document the weakness or behavior, supported languages and constructs, program context, expected analyzer substrate, assumptions, exclusions, and intended claim. A CWE identifier is a taxonomy reference, not an executable proof rule. Avoid broad claims such as "detect all buffer overflows" unless the scope is operationally defined.

## 2. Investigate before writing a rule

Inspect materially different positive and safe cases. Preserve source identity, raw analyzer outputs, exact commands, tool versions, logs, and hashes. Separate:

- direct observations from source or analyzer output;
- derived facts and the method/inputs used to derive them;
- claims that the Evidence engine must establish;
- missing facts that should leave a case unresolved.

A function name or signature may nominate a candidate; it does not prove behavior or data flow.

## 3. Encode and try to falsify the Evidence

Author ELS with explicit bindings, claims, coherent witnesses, counter-evidence, uncertainty policies, and execution budgets. Validate and compile it, then review the Pattern.

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els
python -m evidencelab evidence compile --spec path/to/evidence.els --out /tmp/pattern.json
python -m evidencelab evidence run --spec path/to/evidence.els --graph path/to/canonical-graph.json --out /tmp/result.json
```

Build cases covering:

- **Positive:** the scoped weakness is supported by the required evidence.
- **Safe negative:** a relevant operation exists but the scoped weakness is absent for a reason that can be evidenced.
- **Unknown/incomplete:** available material cannot justify a definitive decision.
- **Counter-evidence:** a condition that refutes or qualifies the same candidate witness.

Use controlled mutations when useful, but record their lineage. Mutations are valuable tests, not independent real-world projects.

## 4. Build defensible experimental material

Choose an exact dataset snapshot, repository commit, suite, or archive. Record licenses, label authority, case IDs, source hashes, mapping/adapter versions, exclusions, and transformations. Keep unknown labels unknown unless there is documented evidence and authority to classify them.

Preview imports before processing a full corpus. Inspect generated case IDs, paths, labels, and relations. An available importer or a large corpus does not automatically make a valid benchmark.

## 5. Control overlap and leakage

Choose splits to match the intended claim: repository, project, CVE, mutation ancestry, or chronology. Keep related cases and mutation descendants in the same partition where appropriate. Use split and leakage audits, inspect warnings, and document the grouping strategy and random seed.

A deterministic split is repeatable, but related cases can still be statistically dependent. Do not count hundreds of near-duplicates or mutations as hundreds of independent projects. Semantic fingerprints can reveal repeated graph scenarios; a unique fingerprint is not, by itself, proof of statistical independence or correct labeling. Review identity, lineage, and provenance separately.

## 6. Report metrics with context

Report confusion-matrix counts and denominators, not only aggregate scores. Keep `UNKNOWN`, `PARTIAL`, infrastructure errors, and incomplete analysis separate unless a documented policy justifies a transformation. Include case coverage, missing cases, witness replay, counter-evidence, source/project identity, split design, leakage checks, analyzer configuration, timeouts, and resource limits.

Confidence intervals should reflect the independent sampling unit. Do not silently remove failed or timed-out cases from denominators.

### Performance measurements

When performance is part of the research claim, use the `performance` command and preserve its report alongside the experiment artifacts:

```bash
python -m evidencelab performance \
  --benchmark path/to/benchmark.json \
  --pattern path/to/pattern.json \
  --repeats 5 \
  --max-case-seconds 60
```

Choose repeat counts and per-case time limits before evaluating the final test set. Record the machine and runtime environment, benchmark and Pattern identities, case coverage, timeouts, and any incomplete runs. Interpret timing results in context: graph size, candidate and path bounds, analyzer cost, and matcher cost may affect different parts of the workflow. Do not treat a timeout or omitted case as a successful fast result. Check `python -m evidencelab performance --help` for the exact options supported by the installed release.

## 7. Use gates appropriately

Commands such as `benchmark-quality`, `benchmark-audit`, `research-readiness`, and `research-check` can enforce configured structural and profile constraints. A passing gate means those checks passed; it does not by itself demonstrate scientific validity or generalization.

A local bundle named "hidden" is not automatically independent. Sealing or HMAC verification may help detect tampering but cannot prove custody or lack of prior access.

## 8. External validation and freeze

A publication or generalization claim needs suitable held-out material and an evaluation process not used to tune the definition, ideally controlled by an independent evaluator. Freeze the ELS and Pattern, source/graph and dataset digests, profile, split manifests, tool/runtime versions, commands, per-case outputs, replay results, and limitations.

A passing unit suite, valid Pattern, single positive case, successful analyzer process, or development `PASS` is not sufficient alone to establish external validity.

## 9. Prepare a research submission

Create a submission manifest from the intended research root, CWE identifier, Pattern, and graph. Add a public benchmark when applicable:

```bash
python -m evidencelab make-submission \
  --root research/cwe-121 \
  --cwe CWE-121 \
  --pattern path/to/pattern.json \
  --graph path/to/graph.json \
  --out /tmp/cwe-121-submission.json
```

Validate the resulting manifest against the profile appropriate to the project and installed release:

```bash
python -m evidencelab validate-submission \
  --submission /tmp/cwe-121-submission.json \
  --profile profiles/research-submission-strict-c-cpp-joern.json
```

Choose a profile appropriate to the intended evaluation. Use `--hidden-benchmark` when the evaluation requires a hidden benchmark. `--hide-cases` and `--report-dir` are additional options; check `python -m evidencelab validate-submission --help` before relying on their exact behavior.

A submission should disclose the research question and scope, exclusions, input identities and label authority, Evidence and Pattern identities, analyzer configuration, unknown or incomplete cases, split and leakage strategy, per-case results, replay findings, limitations, and the gates actually run. A valid submission manifest is not, by itself, evidence of scientific validity or external generalization.

## 10. Useful references

- [MITRE Common Weakness Enumeration (CWE)](https://cwe.mitre.org/): a taxonomy for describing software weaknesses. A CWE identifier helps state scope but does not define executable proof semantics.
- [NIST SARD Juliet Test Suites](https://samate.nist.gov/SARD/test-suites/112): structured test material for weakness-related cases. Treat labels and filename conventions cautiously; confirm the authority and meaning of labels, and preserve unknown labels when evidence is insufficient.
- [JSON Schema](https://json-schema.org/): a standard for describing and validating JSON structure. Schema validity does not establish semantic soundness, correct labels, or research quality.

See also [Evidence reference](evidence-reference.md), [Dataset integration](dataset-integration.md), and [Reproducibility](reproducibility.md).
