# Evidence and ELS reference

Evidence Specification Language (ELS) is the researcher-facing declarative language for defining evidence. It describes concepts, named bindings, claims, coherent witnesses, counter-evidence, execution budgets, uncertainty policies, and provenance expectations.

ELS is not a general-purpose programming language, dataset-mapping language, or replacement for an analyzer's own query language. EvidenceLab validates and executes definitions against supported graph inputs; an external analyzer remains responsible for producing analysis artifacts.

## Basic workflow

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els

python -m evidencelab evidence compile \
  --spec path/to/evidence.els \
  --out /tmp/evidence-pattern.json

python -m evidencelab evidence ir \
  --spec path/to/evidence.els \
  --out /tmp/evidence-ir.json

python -m evidencelab evidence run \
  --spec path/to/evidence.els \
  --graph path/to/canonical-graph.json \
  --out /tmp/evidence-result.json
```

Validation checks the definition contract; compilation produces a reusable Pattern artifact; `ir` emits an intermediate representation for inspection; `run` evaluates the definition against a graph. Use `--help` to inspect the options accepted by your checkout.

## Concepts to define explicitly

A well-scoped definition should make the following reviewable:

- **Concepts and selectors:** which graph entities are candidates and what properties identify them.
- **Slots and bindings:** which entities fill named roles, and which relations must connect them.
- **Claims:** which facts must be established and what evidence supports each fact.
- **Witness coherence:** all required facts must refer to a compatible set of entities, not unrelated nodes assembled into an apparent proof.
- **Counter-evidence:** facts that refute or qualify the same candidate witness.
- **Uncertainty policy and budgets:** how unresolved facts, bounded searches, and incomplete analysis affect the result.
- **Provenance:** which inputs and artifacts support the conclusion.

A node name or function signature can nominate a candidate; it does not by itself prove a causal or data-flow relation.

## Supported selectors and claim kinds

Selectors identify candidate graph nodes. The implementation supports:

| Field | Purpose |
|---|---|
| `type_any` | Match a raw node type against any listed value. |
| `type_all` | Require the raw node type to satisfy every listed value. Multiple distinct values are generally contradictory for a single node and may be flagged by audit. |
| `canonical_type_any` | Match a canonical node type against any listed value. |
| `canonical_type_all` | Require the canonical node type to satisfy every listed value; multiple distinct values are generally contradictory for a single node. |
| `name_any` | Match listed names. |
| `name_regex` | Match a regular expression against the node name or code. |
| `properties` | Require specified property values. |
| `properties_any` | Accept one of the listed values for each specified property. |
| `properties_present` | Require specified properties to be present. |

The supported claim kinds are:

| Claim kind | Purpose |
|---|---|
| `node` | Evaluate a node condition. |
| `node_absence` | Evaluate absence of a node under the available evidence and completeness assumptions. |
| `property` | Check property conditions. |
| `semantic` | Evaluate a normalized semantic fact. |
| `relation` | Require a specified relation between source and target. |
| `relation_any` | Check for a relation using source/target slots or selectors. |
| `relation_none` | Check that the declared relation is absent, subject to completeness. |
| `edge` | Evaluate an edge condition. |
| `path` | Require a path between source and target within the configured bound. |
| `path_absence` | Evaluate absence of an admissible path within a bounded search. |
| `same_object` | Evaluate whether source and target refer to the same object under supported semantics. |
| `compare` | Compare values resolved from property bindings. |
| `range_compare` | Compare numeric ranges conservatively. |
| `cardinality` | Evaluate the count of matching entities or relations. |

Comparison operators accepted by the implementation include `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not_in`, `contains`, and `not_contains`. The required fields depend on the claim kind; a definition must satisfy the current schema rather than relying on the engine to infer missing intent.

## Claim-level proof states

| State | Meaning |
|---|---|
| `PROVEN` | Available facts establish the claim under its declared semantics. |
| `DISPROVEN` | Available facts contradict the claim for the binding being evaluated. |
| `PARTIAL` | Some required evidence or bounded reasoning is available, but the proof is incomplete. |
| `UNKNOWN` | Available artifacts establish neither the claim nor its negation. |
| `NOT_APPLICABLE` | The claim does not apply to an explicitly selected branch; it is not merely missing evidence. |

## Pattern-level outcomes

| Outcome | Meaning |
|---|---|
| `MATCH` | A required coherent witness satisfies the definition and applicable policies. |
| `NO_MATCH` | No admissible witness satisfied the definition on input complete and trustworthy enough for that negative decision. |
| `PARTIAL` | The result is incomplete and must not be reported as a definitive match or negative. |
| `UNKNOWN` | Available evidence is insufficient to decide safely. |

Do not convert a timeout, missing edge, unresolved value, failed export, or truncated search into `NO_MATCH`. The proper result depends on the definition and completeness metadata.

## Bindings, search bounds, and uncertainty policies

Slots bind named roles to candidate graph entities. The current implementation defines a default `max_matches` of 200 per slot. Witness evaluation also has a `max_combinations` bound (default 50,000) and a `distinct_slots` setting (default `true`). Reaching a candidate or combination bound can limit what was examined; do not present a bounded search as exhaustive.

Path claims use `max_hops` (default 12), which must be positive. A path not found within the configured bound does not by itself prove that no path exists outside that bound.

The supported `unknown_policy` values are `unknown`, `non_match`, and `partial`. The supported `counter_unknown_policy` values are `block_match` and `ignore`. These settings affect how unresolved evidence influences the result; choose and document them deliberately. In particular, ignoring unresolved counter-evidence can make a result less conservative. The current ELS parser defaults `counter_unknown_policy` to `block_match`, while parsing a raw pattern with the specification loader defaults an omitted value to `ignore`. For reproducible behavior, set both policies explicitly instead of relying on omitted-field defaults.

## Witnesses and counter-evidence

A witness binds named slots to concrete graph entities. If a definition requires a source, sink, destination, capacity, and write extent, the required relations must hold for the same compatible objects. Evidence about one operation must not be combined with the capacity of an unrelated object.

Counter-evidence should be evaluated against the witness it is intended to refute or qualify. If counter-evidence is unresolved, follow the definition's declared policy; do not silently treat unknown counter-evidence as disproven.

## Recommended test loop

1. Validate and compile the definition.
2. Test it on a minimal positive graph and review the expected witness.
3. Test a safe negative graph.
4. Test incomplete or ambiguous graphs and confirm uncertainty is preserved.
5. Add counterexamples that vary one semantic condition at a time.
6. Replay stored witnesses where supported.
7. Evaluate on distinct projects or repositories and check for source or mutation leakage.
8. Record the definition, compiled artifact, corpus, analyzer version, configuration, and report hashes for reproducibility.

## Limits of validation

A valid ELS document or Pattern means the artifact meets supported structural and semantic contract checks. It does not establish that the research hypothesis is sufficient, that the analyzer recovered every relevant fact, or that results generalize to unseen programs.

For the runtime command catalog, see [CLI reference](cli-reference.md). For research design, see [Research methodology](research-methodology.md).
