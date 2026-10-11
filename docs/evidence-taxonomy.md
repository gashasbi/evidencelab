# Evidence taxonomy

Evidence dimensions describe what kind of semantic fact a claim depends on. They are orthogonal to the source dataset and the name of the analyzer that reported them. A research family may use multiple dimensions in one coherent witness.

## Evidence dimensions

| Dimension | Questions it helps answer | Example observations or derived facts |
|---|---|---|
| Operation evidence | Which operation is being performed? | Call target, operation class, argument roles. |
| Object/state evidence | Which object is read or written, and what is its state? | Object identity, allocation/storage class, field or region identity. |
| Flow evidence | How does a value or control condition reach the operation? | Data flow, reaching definitions, control dependence, call path. |
| Quantitative evidence | Can a required numerical relationship be established? | Extent, capacity, interval bounds, index/range constraints. |
| Guard/control evidence | Is a condition checked and does it dominate or constrain the operation? | Validated length, branch condition, guard outcome. |
| Source/control evidence | What is the origin and trust status of a value? | External input, configuration source, taint or validation status. |
| Analysis-quality evidence | Is the graph complete enough for this claim? | Export status, slice depth, timeout, truncation, unresolved call behavior. |
| Provenance evidence | Can a fact be traced to input artifacts and a derivation? | Source hash, artifact digest, observation ID, derivation method. |
| Witness/coherence evidence | Do all required facts refer to a compatible set of entities? | Shared bindings, same-object relations, connected path. |
| Counter-evidence | What fact would disprove or qualify a candidate? | Safe bounds, validated input, correct guard, safe API behavior. |

## Evidence classes

A class groups patterns by the primary proof shape rather than by dataset name:

- operation identification;
- object identity and state;
- source-to-sink or value propagation;
- control dependence and guard validation;
- quantitative bounds and ranges;
- lifecycle/state transitions;
- configuration and authorization conditions;
- negative or absence claims under an explicit completeness contract;
- composite witnesses that combine multiple classes.

## Coverage matrix

Use `coverage-matrix` to summarize the dimensions and labels represented by a material manifest. A matrix is an inventory, not evidence that every dimension is semantically correct. Review the actual observations, derivations, and witness conditions for each relevant cell.

```bash
python -m evidencelab coverage-matrix \
  --manifest path/to/benchmark.json \
  --out /tmp/coverage-matrix.json
```

A research report should explain which dimensions are exercised, which are absent, and why the omissions do or do not limit the claim.
