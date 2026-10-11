# Research Methodology

### Phase A — Understand the CWE
Record the authoritative weakness definition, intended abstraction level, related CWEs, and what the definition does *not* assert. Do not turn examples into signatures.

### Phase B — Hypotheses
List candidate Evidence Families. Each family must state: what is observed, what is derived, what is proven, what remains unknown, and what would refute the witness.

### Phase C — Graph experiments
Run Joern over direct, interprocedural, cross-file, alias/pointer, storage, guard, and symbolic variants. Preserve raw artifacts and exact query/tool versions.

### Phase D — Executable specification
Encode the hypothesis as an Evidence Pattern with coherent witness bindings. Avoid name-only signatures; prefer semantic call roles, object identity, data flow, ranges, and capacity provenance.

### Phase E — Benchmark
For each family build positive, negative, UNKNOWN, and adversarial cases. Mutate one material property at a time. Every public case has a graph digest and explicit tags.

### Phase F — Evaluation
Measure TP/FP/TN/FN plus UNKNOWN safety and overclaims. Audit duplicate graphs, mutation-label consistency, required dimensions, and provenance.

### Phase G — Hidden validation
Evaluator-owned hidden cases must be external to the researcher workspace. A family should not be promoted on public cases alone.

### Promotion criterion
A family is promoted only when its claims remain machine-matchable and its benchmark meets profile gates without converting UNKNOWN into positive findings.
