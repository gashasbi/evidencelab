# Evidence Specification Language (ELS) reference

## 1. Role and non-goals

The Evidence Specification Language (ELS) is the researcher-facing, declarative way to author a reusable Evidence definition. It describes candidate concepts, named bindings, proof claims, coherent witnesses, counter-evidence, execution bounds, uncertainty policies, and provenance expectations.

ELS is not a general-purpose programming language, dataset mapping language, benchmark language, or replacement for an analyzer's query language. Joern, CodeQL, Semgrep, and other analyzers remain responsible for producing their own analysis artifacts. EvidenceLab validates the Evidence definition and executes its compiled contract over supported graph inputs.

The execution pipeline is:

```text
ELS source
   -> parse and validate
   -> compile to Evidence Pattern / IR
   -> parse and enrich graph input
   -> candidate binding and claim evaluation
   -> coherent witness / counter-evidence / uncertainty
   -> machine-readable result
```

## 2. Authoring and execution commands

```bash
python -m evidencelab evidence validate --spec path/to/evidence.els
python -m evidencelab evidence compile --spec path/to/evidence.els --out /tmp/evidence-pattern.json
python -m evidencelab evidence ir --spec path/to/evidence.els --out /tmp/evidence-ir.json
python -m evidencelab evidence run \
  --spec path/to/evidence.els \
  --graph path/to/canonical-graph.json \
  --out /tmp/evidence-result.json
```

`validate` checks the source contract; `compile` produces the public Evidence Pattern; `ir` emits the intermediate representation for review; `run` executes the definition against a supported graph. `--audit` can be supplied to `evidence run` when an audit payload is needed with the result.

Validation is a structural and semantic contract check. It does not establish external validity or prove that the chosen Evidence is sufficient for every program variant.

## 3. Top-level declaration

A typical definition looks like this:

```text
evidence "cwe-121.fixed-write-001" {
  cwe "CWE-121"
  name "Fixed-extent write beyond an automatic local array"
  version "1.0.0"
  language "C/C++"
  family_id "cwe-121-fixed-write"
  description "Detect a write whose proven extent exceeds the destination capacity."

  unknown_policy "unknown"
  counter_unknown_policy "block_match"
  path_budget {"max_hops":12,"max_paths_per_claim":100}

  concept "memory_write" {
    selector {
      canonical_type_any ["CALL"]
      name_any ["memcpy"]
    }
  }

  slot "sink" {
    concept "memory_write"
    required true
    max_matches 100
  }

  claim "sink_exists" {
    kind "node"
    required true
    slot "sink"
  }

  witness "W1" {
    slots ["sink"]
    claims ["sink_exists"]
    required true
  }
}
```

This is a syntax illustration, not a sufficient research-grade CWE-121 definition. The full bundled example, `examples/evidence-dsl/cwe121-fixed-write-research-grade.els`, demonstrates a richer contract.

## 4. Concepts and selectors

A concept describes which graph nodes may be candidates for a named role. Canonical node types should be preferred when the definition is intended to survive analyzer changes.

Supported selector fields include:

- `type_any`, `type_all`;
- `canonical_type_any`, `canonical_type_all`;
- `name_any`, `name_regex`;
- `properties`, `properties_any`, `properties_present`.

Example:

```text
concept "copy_call" {
  selector {
    canonical_type_any ["CALL"]
    name_any ["memcpy", "memmove"]
  }
}
```

Raw analyzer node labels may be useful during exploration or in explicitly analyzer-specific definitions. Such use should be documented as an adapter dependency, not described as analyzer-independent semantics.

## 5. Slots and binding budgets

A slot gives a name to a candidate entity or role that claims can reference:

```text
slot "sink" {
  concept "copy_call"
  required true
  max_matches 100
}
```

Slots are inputs to coherent witness construction. A slot-level candidate cap is an execution bound: if the cap truncates the candidate space, EvidenceLab must not silently present the search as exhaustive. Keep the cap appropriate to the graph and include it in reproducibility records.

## 6. Claim kinds

The current Evidence Pattern contract supports these claim kinds:

| Claim kind | Purpose |
|---|---|
| `node` | Establish a node or slot-related node condition. |
| `node_absence` | Establish absence under the declared graph and completeness assumptions. |
| `property` | Check a node or property condition. |
| `semantic` | Check a normalized semantic fact. |
| `relation` | Require a specific graph relation between bound entities. |
| `relation_any` | Accept one of a declared set of relations. |
| `relation_none` | Require that none of a declared set of relations exists, subject to completeness rules. |
| `edge` | Check an edge-level condition. |
| `path` | Require a relation path between bound source and target within an explicit budget. |
| `path_absence` | Check that an admissible path is absent under a bounded, sufficiently complete search. |
| `same_object` | Require two references to denote the same object under the implemented semantic relation. |
| `compare` | Compare values obtained from declared property bindings. |
| `range_compare` | Compare numeric ranges conservatively. |
| `cardinality` | Constrain the number of matching entities or relations. |

A claim must use the properties and references supported by the implementation and current schema. Unknown fields or unsupported semantics should be treated as a validation problem, not as an instruction that the engine will infer what was intended.

## 7. Relations and paths

Example of a bounded data-flow path:

```text
claim "input_reaches_sink" {
  kind "path"
  required true
  source "source"
  target "sink"
  relation "DATA_FLOW"
  max_hops 12
  description "The selected source reaches the write operation."
}
```

Path bounds are both performance controls and semantic limitations. If an acceptable path might exist beyond the configured bound, a negative conclusion cannot be promoted to proof of absence. Record the bound and its rationale in the pattern and experiment.

## 8. Quantitative constraints

Example of a scalar comparison:

```text
claim "extent_exceeds_capacity" {
  kind "compare"
  required true
  left {
    slot "extent"
    property "derived.numeric_value"
  }
  operator ">"
  right {
    slot "destination"
    property "derived.length"
  }
}
```

The compared values must come from supported properties and must carry sufficient derivation/provenance context. For interval or range reasoning, the matcher is conservative: an ordering is `PROVEN` only when the represented ranges establish it. Overlap, missing bounds, or unresolved symbolic values remain uncertain.

## 9. Witnesses and coherence

A witness is one consistent assignment of graph entities to Evidence roles. For example:

```text
source -> data-flow path -> sink
                          |
                          +-> destination object -> capacity
                          +-> write extent
```

All required claims must hold under one witness binding. EvidenceLab must not combine a source path from one function with an unrelated sink or destination from another function to manufacture a proof.

A witness may list `slots`, required `claims`, and relevant `counter_claims`. Controls such as `distinct_slots` and `max_combinations` affect which bindings can be considered. Candidate and combination limits must be reported as part of the execution configuration; hitting a bound can make a decision incomplete.

## 10. Counter-evidence

Counter-evidence records a concrete condition that can refute, qualify, or disqualify a candidate witness. It is evaluated against the same relevant witness binding.

For example, if positive Evidence requires `extent > capacity`, a counter-claim can require `extent <= capacity`. A counter-claim that is `DISPROVEN` means that refuting condition does not hold; it is not itself a matcher failure.

`counter_unknown_policy "block_match"` prevents unresolved counter-evidence from being treated as if it were absent. This is important when a safe condition cannot be established because the source or analyzer export is incomplete.

## 11. Uncertainty and completeness policies

Definitions may specify policies such as `unknown_policy`, `counter_unknown_policy`, and `path_budget`. These are observable parts of the definition, not implementation details to ignore. A conservative policy must preserve the difference between:

- an explicitly refuted claim;
- a claim that cannot be evaluated from available information;
- a claim that does not apply to a selected branch;
- a complete search that found no admissible witness;
- a bounded or degraded search that cannot establish absence.

Do not turn a failed Joern command, truncated candidate search, malformed graph, or absent property into evidence that the source is safe.

## 12. Research-grade metadata

Depending on the research task, add explicit metadata for:

- CWE and external source references;
- language, Evidence family, and intended scope;
- required graph/observation semantics and analyzer assumptions;
- positive, negative, and unknown coverage;
- counter-evidence expectations;
- provenance for derived facts and input artifacts;
- analysis completeness and witness requirements;
- path/search budgets and runtime bounds;
- limitations and conditions under which the definition is not applicable.

`research-audit`, `research-check`, `research-readiness`, and profile-based evaluation verify different aspects of the wider research package. No single `evidence validate` call can substitute for all of them.

## 13. Recommended test loop

1. Validate and compile the definition.
2. Execute it on a minimal positive graph with a manually reviewed expected witness.
3. Execute it on a safe negative graph.
4. Execute it on incomplete or ambiguous graphs and confirm that uncertainty is preserved.
5. Add counterexamples that vary one semantic dimension at a time.
6. Independently replay stored witnesses.
7. Evaluate on distinct projects or repositories and avoid source/mutation leakage.
8. Freeze the source definition, compiled artifact, corpus, analyzer version, configuration, and report hashes before publication.

See [Evidence model](evidence-model.md), [Benchmark design](benchmark-design.md), and [Research methodology](research-methodology.md).
