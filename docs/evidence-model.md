# Evidence model

## 1. The proof chain

EvidenceLab separates the source of a statement from the logic that uses it:

```text
Raw artifact or analyzer result
             |
             v
Observation with source identity and provenance
             |
             v
Derived fact with named inputs and method
             |
             v
Evidence claim evaluated under a coherent binding
             |
             v
Witness, counter-evidence, uncertainty, and outcome
```

A parser finding a property in a graph is an observation. A deterministic rule that calculates a buffer capacity is a derivation. The statement that a write extent exceeds that capacity is an Evidence claim. The final `MATCH` is a result of satisfying the required claims under one witness, not a reflection of a dataset label.

## 2. Claim-level proof states

| State | Meaning | Appropriate interpretation |
|---|---|---|
| `PROVEN` | Available facts establish the claim under its declared semantics. | The claim is satisfied for this binding. |
| `DISPROVEN` | Available facts contradict the claim. | This binding does not establish the claim. |
| `PARTIAL` | Only part of the required evidence or bounded reasoning is available. | Do not treat as a complete proof. |
| `UNKNOWN` | Available artifacts do not establish or refute the claim. | More analysis or information may be required. |
| `NOT_APPLICABLE` | The claim is not required on an explicitly selected branch. | This is different from missing evidence. |

## 3. Pattern-level outcomes

| Outcome | Meaning |
|---|---|
| `MATCH` | A required, coherent witness satisfies the Evidence definition and applicable policies. |
| `NO_MATCH` | The definition is not satisfied by a sufficiently complete and trustworthy input for the decision. |
| `PARTIAL` | Execution or a declared policy permits a partial result that cannot be promoted to a definitive match. |
| `UNKNOWN` | The available evidence cannot safely determine the outcome. |

The distinction between `NO_MATCH` and `UNKNOWN` is a core safety property. A missing data-flow edge may mean that the program has no such flow, or that the analyzer did not emit it. The correct result depends on the completeness contract and the available evidence.

## 4. Coherent witnesses

A witness is a consistent mapping from Evidence slots to graph entities. If the Evidence requires a source, sink, destination object, capacity, and write extent, the engine must prove the required relationships for the same selected entities. It cannot use an unrelated object to satisfy the capacity claim and a different operation to satisfy the sink claim.

Witness coherence is a semantic guard against accidental proof assembly from disconnected parts of a graph. It is also the reason stored witnesses can be validated independently.

## 5. Counter-evidence

Counter-evidence is associated with the same witness that the positive claims describe. Examples include a proven length guard, a write extent no greater than destination capacity, a destination with the wrong object identity, or a safe operation semantic.

A refuting claim being `DISPROVEN` is not a global failure. It means that the refuting condition is not satisfied for this witness. An `UNKNOWN` counter-claim must follow the declared policy; it must not be silently treated as false.

## 6. Analysis completeness

A graph may pass structural parsing and still omit facts relevant to a decision. Examples include:

- a data-flow slice without the complete source graph;
- GraphML export loss of list-valued properties;
- a timeout during interprocedural analysis;
- a depth-limited search;
- a candidate cap that truncates bindings;
- missing source, line, type, or object identity metadata;
- unresolved aliases or external-library behavior.

When the Evidence definition depends on facts that these limitations may have hidden, absence is not proof of safety. Preserve the analyzer's completeness report and use conservative outcomes.

## 7. Provenance and replay

For each derived fact, preserve identified inputs and the derivation method. For each evaluated result, retain the Evidence Pattern identity/digest, graph identity/digest, matcher configuration, witness binding, counter-evidence, outcome, and software/analyzer versions as available.

Witness replay validates a stored binding without repeating candidate discovery. It answers a narrower question than a complete scan: given this pattern, graph, and stored witness, do the bound claims still hold? A replay result cannot compensate for an incomplete graph or an invalid benchmark design.

See [Reproducibility](reproducibility.md), [Witness validation](witness-validation.md), and [Security model](security-model.md).
