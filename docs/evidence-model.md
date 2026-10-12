# Evidence model

This page defines what EvidenceLab's outcomes mean. For ELS syntax, use the [ELS reference](evidence-dsl.md); for the execution components, see [Architecture](architecture.md).

## From input to outcome

```text
Raw artifact or analyzer result
             -> observation with identity/provenance
             -> derived fact with inputs and method
             -> Evidence claim evaluated under a binding
             -> witness, counter-evidence, uncertainty, outcome
```

An external label is not an observation, a derived fact is not automatically proven, and a result is not merely a reflection of a dataset label.

## Claim-level proof states

| State | Meaning |
|---|---|
| `PROVEN` | Available facts establish the claim under its declared semantics. |
| `DISPROVEN` | Available facts contradict the claim for this binding. |
| `PARTIAL` | Only part of the required evidence or bounded reasoning is available. |
| `UNKNOWN` | Available artifacts establish neither the claim nor its negation. |
| `NOT_APPLICABLE` | The claim does not apply to an explicitly selected branch; it is not missing evidence. |

## Pattern-level outcomes

| Outcome | Meaning |
|---|---|
| `MATCH` | A required, coherent witness satisfies the definition and applicable policies. |
| `NO_MATCH` | No admissible witness satisfied the definition on input sufficiently complete and trustworthy for that decision. |
| `PARTIAL` | The result is explicitly incomplete and must not be treated as a definitive match. |
| `UNKNOWN` | Available evidence is insufficient to decide safely. |

Do not turn a timeout, missing edge, unresolved value, failed export, or truncated candidate search into `NO_MATCH`. The correct outcome depends on the definition and the completeness information available.

## Witness coherence

A witness binds named Evidence slots to concrete graph entities. If a definition requires a source, sink, destination, capacity, and write extent, every required relation must hold for the same compatible entities. The engine must not combine a path from one operation with the capacity of an unrelated object.

## Counter-evidence

Counter-evidence is evaluated against the candidate witness it is intended to refute or qualify. For example, `extent <= capacity` may refute a positive claim that requires `extent > capacity`. A counter-claim in `DISPROVEN` state means that the refuting condition does not hold; an `UNKNOWN` counter-claim must follow the declared policy and must not silently count as false.

## Completeness and limits

A syntactically valid graph can omit semantically important facts. Common causes include partial data-flow slices, lossy export properties, unresolved aliases or library behavior, timeouts, depth limits, and candidate/combination caps. Record the relevant configuration and preserve degraded states. A complete search over a bounded graph answers only the question represented by that graph and bound.

## Evidence dimensions

A reusable definition can combine several dimensions in one witness. Use this table to check what the research question actually requires; the categories are a review aid, not proof that a definition handles each dimension correctly.

| Dimension | Review question | Example fact |
|---|---|---|
| Operation | Which operation and argument roles matter? | Call target, destination argument. |
| Object/state | Which object is involved, and what is its state? | Object identity, storage lifetime, capacity. |
| Flow | How does a value reach the operation? | Data-flow edge, reaching definition, call path. |
| Control/guard | Is a check effective for this operation? | Bounds check and its relation to the write. |
| Quantitative | Can the required numeric relation be proved? | Extent exceeds a proven capacity. |
| Source/trust | Where did the value originate, and was it validated? | External input, validated length. |
| Analysis quality | Is the graph complete enough for this claim? | Timeout, truncated slice, unresolved call. |
| Provenance | Can a fact be traced to inputs and derivation? | Source digest, observation ID, method. |
| Coherence/counter-evidence | Do claims use compatible entities, and what could refute them? | Same-object binding, safe extent, correct guard. |

## Review checklist

Before relying on an Evidence Pattern, review:

1. whether bindings identify the same objects and operations;
2. whether required relations and quantitative assumptions are justified;
3. what could refute the witness or qualify its interpretation;
4. how missing facts, timeouts, truncation, and unresolved values are handled;
5. whether derived facts name their inputs and method;
6. whether positive, safe-negative, unknown, and counter-evidence cases challenge the definition.

Prefer canonical graph relations when cross-analyzer reuse is intended. If raw analyzer properties are necessary, document that dependency.

## Witness replay

Replay checks a stored fixed binding against a graph and Pattern without repeating candidate discovery. It can catch changed artifacts or invalid witness claims, but it cannot discover an unstored witness, repair an incomplete graph, or establish external generalization. See [Reproducibility](reproducibility.md).
