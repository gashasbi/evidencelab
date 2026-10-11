from __future__ import annotations
from . import SCHEMA_VERSION
from dataclasses import dataclass, asdict, field
from typing import Any
import itertools
import re
import copy
from .models import Graph, Node
from .semantics import get_property, enrich_graph, semantic_edge_types, node_value_range
from .spec import Claim, Pattern, Selector, Slot, Witness
from .evidence import EvidenceLedger, EvidenceItem, EvidenceRef
from .canonical import canonicalize_graph, canonical_validation
from .outcomes import normalize_proof_state


def _value_equal(a: Any, b: Any) -> bool:
    if isinstance(b, str) and isinstance(a, (int, float)):
        try:
            return a == float(b)
        except Exception:
            return False
    if isinstance(a, str) and isinstance(b, (int, float)):
        try:
            return float(a) == b
        except Exception:
            return False
    if isinstance(a, str) and isinstance(b, str):
        return a == b or a.upper() == b.upper()
    return a == b


def _properties_match(
    node: Node,
    equals: dict[str, Any],
    any_of: dict[str, list[Any]],
    present: list[str] | None = None,
) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for k, expected in equals.items():
        actual = get_property(node, k, None)
        if actual is None:
            missing.append(k)
        elif not _value_equal(actual, expected):
            return False, []
    for k, values in any_of.items():
        actual = get_property(node, k, None)
        if actual is None:
            missing.append(k)
        elif not any(_value_equal(actual, v) for v in values):
            return False, []
    for k in present or []:
        if get_property(node, k, None) is None:
            missing.append(k)
    return (not missing), missing


def _edge_properties_match(
    edge: Any, equals: dict[str, Any], any_of: dict[str, list[Any]]
) -> tuple[bool, list[str]]:
    missing: list[str] = []
    props = getattr(edge, "properties", {}) or {}
    for k, expected in equals.items():
        actual = props.get(k)
        if actual is None:
            # tolerate Joern naming variants
            actual = next(
                (
                    v
                    for kk, v in props.items()
                    if str(kk).replace("_", "").lower()
                    == str(k).replace("_", "").lower()
                ),
                None,
            )
        if actual is None:
            missing.append(k)
        elif not _value_equal(actual, expected):
            return False, []
    for k, values in any_of.items():
        actual = props.get(k)
        if actual is None:
            actual = next(
                (
                    v
                    for kk, v in props.items()
                    if str(kk).replace("_", "").lower()
                    == str(k).replace("_", "").lower()
                ),
                None,
            )
        if actual is None:
            missing.append(k)
        elif not any(_value_equal(actual, v) for v in values):
            return False, []
    return (not missing), missing


def _node_match_record(node: Node) -> dict[str, Any]:
    rec: dict[str, Any] = {"node": node.id}
    for key, aliases in (
        ("file", ("filename", "FILENAME", "parentFile", "parent_file")),
        ("line", ("lineNumber", "LINE_NUMBER", "line")),
        ("column", ("columnNumber", "COLUMN_NUMBER", "column")),
        ("code", ("code", "CODE")),
    ):
        value = next(
            (node.get(a) for a in aliases if node.get(a) not in (None, "")), None
        )
        if value is not None:
            rec[key] = value
    return rec


def _selector_matches(node: Node, selector: Selector) -> bool:
    # Canonical selectors keep matching independent of Joern-specific node labels.
    if selector.type_any and node.type not in set(selector.type_any):
        return False
    if selector.type_all and any(node.type != t for t in selector.type_all):
        return False
    canonical_type = str(
        (node.properties.get("derived") or {}).get("canonical_node_type", node.type)
    ).upper()
    if selector.canonical_type_any and canonical_type not in set(
        selector.canonical_type_any
    ):
        return False
    if selector.canonical_type_all and any(
        canonical_type != t for t in selector.canonical_type_all
    ):
        return False
    name = str(get_property(node, "derived.name", node.name) or "")
    alternatives = {
        str(node.get("name", "")),
        str(node.get("fullName", "")),
        str(node.get("methodFullName", "")),
        name,
    }
    if selector.name_any and not any(x in alternatives for x in selector.name_any):
        return False
    if selector.name_regex:
        if (
            re.search(selector.name_regex, name) is None
            and re.search(selector.name_regex, str(node.get("code", ""))) is None
        ):
            return False
    ok, _ = _properties_match(
        node, selector.properties, selector.properties_any, selector.properties_present
    )
    return ok


@dataclass(slots=True)
class ClaimResult:
    claim_id: str
    kind: str
    status: str
    required: bool
    description: str
    matches: list[dict[str, Any]]
    explanation: str
    proof_level: str = "PROVEN"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WitnessResult:
    witness_id: str
    status: str
    bindings: dict[str, str]
    claims: list[ClaimResult]
    counter_evidence: list[ClaimResult]
    explanation: str
    combination_count: int = 0
    matched_bindings: list[dict[str, str]] = field(default_factory=list)
    rejection_summary: dict[str, int] = field(default_factory=dict)
    search_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MatchResult:
    pattern_id: str
    cwe: str
    status: str
    slots: dict[str, list[str]]
    claims: list[ClaimResult]
    counter_evidence: list[ClaimResult]
    witnesses: list[WitnessResult]
    evidence_trace: dict[str, Any]
    warnings: list[str]
    ledger: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Matcher:
    """Safe graph evidence matcher.

    The matcher is deliberately conservative:
    - missing evidence on an incomplete graph becomes UNKNOWN, not DISPROVEN;
    - candidate truncation prevents a definitive MATCH;
    - degraded parser health prevents a definitive MATCH;
    - all required claims must hold for one coherent witness binding;
    - counter evidence is evaluated against the same binding.
    """

    def __init__(
        self,
        graph: Graph,
        max_global_combinations: int = 200_000,
        max_witness_alternatives: int = 25,
        hard_max_hops: int = 24,
        require_analyzer_attestation: bool = False,
    ):
        # Keep enrichment derived-only so caller data, artifact digests, and replay stay stable.
        self.raw_graph_digest = graph.digest()
        self.graph = canonicalize_graph(graph)
        self.max_global_combinations = int(max_global_combinations)
        self.max_witness_alternatives = int(max_witness_alternatives)
        self.hard_max_hops = int(hard_max_hops)
        self.require_analyzer_attestation = bool(require_analyzer_attestation)

    @staticmethod
    def _is_complete(g: Graph) -> bool:
        # Treat programmatic graphs as caller-declared; preserve explicit degraded-state metadata.
        completeness = g.metadata.get("completeness") or "declared"
        parse_health = g.metadata.get("parse_health") or "OK"
        return completeness in {"full_export", "declared"} and parse_health == "OK"

    @staticmethod
    def _unknown_status(pattern: Pattern) -> str:
        if pattern.unknown_policy == "partial":
            return "PARTIAL"
        if pattern.unknown_policy == "non_match":
            return "NO_MATCH"
        return "UNKNOWN"

    def run(self, pattern: Pattern) -> MatchResult:
        slots: dict[str, list[str]] = {}
        warnings: list[str] = []
        truncated_slots: dict[str, dict[str, int]] = {}
        for sid, slot in pattern.slots.items():
            candidates = self._nodes_for_slot(slot, pattern)
            original = len(candidates)
            if original > slot.max_matches:
                warnings.append(
                    f"slot {sid} truncated from {original} to {slot.max_matches} candidates"
                )
                truncated_slots[sid] = {"original": original, "kept": slot.max_matches}
            slots[sid] = [n.id for n in candidates[: slot.max_matches]]

        used_positive = {
            c.id for w in pattern.witnesses for c in pattern.claims if c.id in w.claims
        }
        used_counter = {
            c.id
            for w in pattern.witnesses
            for c in pattern.counter_claims
            if c.id in w.counter_claims
        }
        global_claims = [
            self._claim(c, slots) for c in pattern.claims if c.id not in used_positive
        ]
        global_counters = [
            self._claim(c, slots)
            for c in pattern.counter_claims
            if c.id not in used_counter
        ]
        witness_results = [
            self._evaluate_witness(w, pattern, slots) for w in pattern.witnesses
        ]

        if (self.graph.metadata.get("parse_health") or "OK") != "OK":
            warnings.append(
                f"graph parse health={self.graph.metadata.get('parse_health')}"
            )
        if self.graph.metadata.get("completeness") not in {
            None,
            "full_export",
            "declared",
        }:
            warnings.append(
                f"graph completeness={self.graph.metadata.get('completeness')}"
            )
        if self.graph.metadata.get("candidate_truncated") or self.graph.metadata.get(
            "analysis_truncated"
        ):
            warnings.append(
                "analysis reported truncation; definitive MATCH is suppressed"
            )
        if self.graph.metadata.get("loss_risk", {}).get("graphml_lists"):
            warnings.append(
                "GraphML may omit list-valued properties; prefer GraphSON when list properties are material"
            )
        if truncated_slots:
            warnings.append(
                "candidate truncation occurred; definitive MATCH is suppressed"
            )

        analysis_incomplete = (
            bool(truncated_slots)
            or (self.graph.metadata.get("parse_health") or "OK") != "OK"
            or (self.graph.metadata.get("completeness") or "declared")
            not in {"full_export", "declared"}
            or bool(self.graph.metadata.get("candidate_truncated"))
            or bool(self.graph.metadata.get("analysis_truncated"))
        )
        attestation = self.graph.metadata.get("analysis_attestation") or {}
        attestation_level = str(attestation.get("level", "")).upper()
        if self.require_analyzer_attestation and attestation_level not in {
            "ANALYZER_ATTESTED",
            "BENCHMARK_ASSERTED",
        }:
            analysis_incomplete = True
            warnings.append(
                "analyzer attestation is required for definitive publication evaluation"
            )
        # Missing or partial required analysis is information loss, not evidence of absence.
        required_dims = set()
        required_dims.update(
            str(x)
            for x in (
                pattern.semantic_contract.get("required_analysis_dimensions", [])
                if isinstance(pattern.semantic_contract, dict)
                else []
            )
        )
        required_dims.update(
            str(x)
            for x in (
                pattern.evidence_contract.get("required_analysis_dimensions", [])
                if isinstance(pattern.evidence_contract, dict)
                else []
            )
        )
        completeness_manifest = self.graph.metadata.get("analysis_completeness") or {}
        aliases = {
            "data_flow": "dataflow",
            "dataflow": "dataflow",
            "call_graph": "interprocedural",
            "object": "object_identity",
            "range": "numeric_range",
            "control": "control_flow",
        }
        for dim in required_dims:
            actual = aliases.get(dim, dim)
            state = str(completeness_manifest.get(actual, "UNKNOWN")).upper()
            if state not in {"COMPLETE", "FULL", "PROVEN"}:
                analysis_incomplete = True
                warnings.append(
                    f"required analysis dimension is not complete: {actual}={state}"
                )

        if pattern.witnesses:
            required = [
                wr for wr, w in zip(witness_results, pattern.witnesses) if w.required
            ]
            if any(w.status == "MATCH" for w in required) and not analysis_incomplete:
                status = "MATCH"
            elif any(w.status == "MATCH" for w in required) and analysis_incomplete:
                status = self._unknown_status(pattern)
            elif any(w.status == "UNKNOWN" for w in required):
                status = (
                    "UNKNOWN"
                    if pattern.unknown_policy == "unknown"
                    else self._unknown_status(pattern)
                )
            elif any(w.status == "PARTIAL" for w in required):
                status = "PARTIAL"
            else:
                status = "NO_MATCH"
        else:
            required = [c for c in global_claims if c.required]
            if any(c.status == "PROVEN" for c in global_counters):
                status = "NO_MATCH"
            elif any(c.status == "UNKNOWN" for c in required):
                status = self._unknown_status(pattern)
            elif any(c.status == "DISPROVEN" for c in required):
                status = "NO_MATCH"
            else:
                status = (
                    "MATCH"
                    if not truncated_slots
                    and (self.graph.metadata.get("parse_health") or "OK") == "OK"
                    else "PARTIAL"
                )

        all_wclaims = [c for w in witness_results for c in w.claims]
        all_wcounter = [c for w in witness_results for c in w.counter_evidence]
        canonical_check = canonical_validation(self.graph)
        trace = {
            "schema_version": pattern.schema_version,
            "evidencelab_schema_version": SCHEMA_VERSION,
            "canonical_graph": canonical_check,
            "graph_digest": self.raw_graph_digest,
            "pattern_digest": __import__(
                "evidencelab.provenance", fromlist=["sha256_json"]
            ).sha256_json(
                {
                    "pattern_id": pattern.pattern_id,
                    "version": pattern.version,
                    "schema_version": pattern.schema_version,
                    "cwe": pattern.cwe,
                    "claims": [c.id for c in pattern.claims],
                    "counter_claims": [c.id for c in pattern.counter_claims],
                    "witnesses": [w.id for w in pattern.witnesses],
                }
            ),
            "analysis_incomplete": analysis_incomplete,
            "proved_claims": [
                c.claim_id
                for c in (global_claims + all_wclaims)
                if c.status == "PROVEN"
            ],
            "disproved_claims": [
                c.claim_id
                for c in (global_claims + all_wclaims)
                if c.status == "DISPROVEN"
            ],
            "unknown_claims": [
                c.claim_id
                for c in (global_claims + all_wclaims)
                if c.status == "UNKNOWN"
            ],
            "matching_witnesses": [
                w.witness_id for w in witness_results if w.status == "MATCH"
            ],
            "partial_witnesses": [
                w.witness_id for w in witness_results if w.status == "PARTIAL"
            ],
            "proved_counter_evidence": [
                c.claim_id for c in global_counters if c.status == "PROVEN"
            ]
            + [c.claim_id for c in all_wcounter if c.status == "PROVEN"],
            "disproved_counter_evidence": [
                c.claim_id for c in global_counters if c.status == "DISPROVEN"
            ]
            + [c.claim_id for c in all_wcounter if c.status == "DISPROVEN"],
            "unknown_counter_evidence": [
                c.claim_id for c in global_counters if c.status == "UNKNOWN"
            ]
            + [c.claim_id for c in all_wcounter if c.status == "UNKNOWN"],
            "candidate_truncation": truncated_slots,
            "graph_complete_for_absence": self._is_complete(self.graph),
            "analyzer_attestation": attestation,
            "analyzer_attestation_required": self.require_analyzer_attestation,
            "witness_search_complete": all(w.search_complete for w in witness_results),
            "witness_search_complete_by_id": {
                w.witness_id: w.search_complete for w in witness_results
            },
            "witness_claim_status_counts": {
                "PROVEN": sum(c.status == "PROVEN" for c in all_wclaims),
                "DISPROVEN": sum(c.status == "DISPROVEN" for c in all_wclaims),
                "UNKNOWN": sum(c.status == "UNKNOWN" for c in all_wclaims),
                "NOT_APPLICABLE": sum(
                    c.status == "NOT_APPLICABLE" for c in all_wclaims
                ),
            },
        }
        from .canonical import semantic_graph_fingerprint

        trace["semantic_graph_fingerprint"] = semantic_graph_fingerprint(self.graph)
        # Evidence quality signals; these are descriptive until the benchmark profile binds gates.
        matched_witnesses = [w for w in witness_results if w.status == "MATCH"]
        trace["evidence_quality"] = {
            "witness_count": len(witness_results),
            "matched_witness_count": len(matched_witnesses),
            "avg_claims_per_witness": (
                sum(len(w.claims) for w in matched_witnesses) / len(matched_witnesses)
            )
            if matched_witnesses
            else 0.0,
            "avg_witness_bindings": (
                sum(len(w.bindings) for w in matched_witnesses) / len(matched_witnesses)
            )
            if matched_witnesses
            else 0.0,
            "search_complete_rate": (
                sum(bool(w.search_complete) for w in witness_results)
                / len(witness_results)
            )
            if witness_results
            else 0.0,
        }
        ledger = EvidenceLedger()

        def add_claim(cr: ClaimResult, counter: bool = False) -> None:
            refs = [EvidenceRef("artifact", self.raw_graph_digest)]
            for match in cr.matches[:50]:
                for key, value in match.items():
                    if key.endswith("node") or key in {
                        "node",
                        "path",
                        "source",
                        "target",
                        "edge",
                    }:
                        if isinstance(value, (list, tuple)):
                            refs.extend(EvidenceRef("graph", str(v)) for v in value)
                        elif value is not None:
                            refs.append(EvidenceRef("graph", str(value)))
            ledger.add(
                EvidenceItem(
                    id=("COUNTER:" if counter else "CLAIM:") + cr.claim_id,
                    kind=EvidenceKind.COUNTER.value
                    if counter
                    else EvidenceKind.FACT.value,
                    state=cr.status,
                    statement=cr.description,
                    value={
                        "kind": cr.kind,
                        "matches": cr.matches[:50],
                        "explanation": cr.explanation,
                    },
                    provenance=refs,
                    tags=["counter_evidence"]
                    if counter
                    else ["derived_fact", "positive_evidence"],
                )
            )

        from .evidence import EvidenceKind

        for cr in global_claims:
            add_claim(cr, False)
        for cr in global_counters:
            add_claim(cr, True)
        for wr in witness_results:
            for cr in wr.claims:
                add_claim(cr, False)
            for cr in wr.counter_evidence:
                add_claim(cr, True)
        return MatchResult(
            pattern.pattern_id,
            pattern.cwe,
            status,
            slots,
            global_claims,
            global_counters,
            witness_results,
            trace,
            warnings,
            ledger.to_dict(),
        )

    def _nodes_for_slot(self, slot: Slot, pattern: Pattern) -> list[Node]:
        concept = pattern.concepts[slot.concept]
        selectors = concept.selectors + slot.selector_overrides
        if concept.mode == "all":
            return [
                n
                for n in self.graph.nodes.values()
                if all(_selector_matches(n, s) for s in selectors)
            ]
        return [
            n
            for n in self.graph.nodes.values()
            if any(_selector_matches(n, s) for s in selectors)
        ]

    def _evaluate_witness(
        self, witness: Witness, pattern: Pattern, slots: dict[str, list[str]]
    ) -> WitnessResult:
        option_lists: list[list[str | None]] = []
        active: list[str] = []
        for sid in witness.slots:
            vals = slots.get(sid, [])
            if not vals:
                if pattern.slots[sid].required:
                    return WitnessResult(
                        witness.id,
                        self._unknown_status(pattern)
                        if not self._is_complete(self.graph)
                        else "NO_MATCH",
                        {},
                        [],
                        [],
                        f"required slot empty: {sid}",
                        search_complete=self._is_complete(self.graph),
                        rejection_summary={"EMPTY_SLOT": 1},
                    )
                vals = [None]
            active.append(sid)
            option_lists.append(vals)
        total = 1
        for vals in option_lists:
            total *= len(vals)
        if total > witness.max_combinations:
            return WitnessResult(
                witness.id,
                "PARTIAL",
                {},
                [],
                [],
                f"candidate combinations {total} exceed witness limit {witness.max_combinations}",
                combination_count=0,
                search_complete=False,
                rejection_summary={"COMBINATION_LIMIT": 1},
            )

        byid = {c.id: c for c in pattern.claims + pattern.counter_claims}
        required_claims = [byid[cid] for cid in witness.claims]
        counters = [byid[cid] for cid in witness.counter_claims]
        groups = [
            [byid[cid] for cid in group] for group in pattern.required_claim_groups
        ]
        combinations = 0
        matched: list[dict[str, str]] = []
        saw_unknown = False
        rejection: dict[str, int] = {}
        best: tuple[dict[str, str], list[ClaimResult], list[ClaimResult]] | None = None
        best_score = -(10**9)

        for values in itertools.product(*option_lists):
            combinations += 1
            binding = {sid: str(v) for sid, v in zip(active, values) if v is not None}
            if witness.distinct_slots and len(binding.values()) != len(
                set(binding.values())
            ):
                rejection["NON_DISTINCT"] = rejection.get("NON_DISTINCT", 0) + 1
                continue
            claim_results = [
                self._claim_with_binding(c, binding, slots) for c in required_claims
            ]
            counter_results = [
                self._claim_with_binding(c, binding, slots) for c in counters
            ]
            score = sum(c.status == "PROVEN" for c in claim_results) - 2 * sum(
                c.status == "DISPROVEN" for c in claim_results
            )
            if score > best_score:
                best_score = score
                best = (binding, claim_results, counter_results)

            if any(x.status == "PROVEN" for x in counter_results):
                rejection["COUNTER_EVIDENCE"] = rejection.get("COUNTER_EVIDENCE", 0) + 1
                continue
            if pattern.counter_unknown_policy == "block_match" and any(
                x.status == "UNKNOWN" for x in counter_results
            ):
                saw_unknown = True
                rejection["COUNTER_UNKNOWN"] = rejection.get("COUNTER_UNKNOWN", 0) + 1
                continue
            if any(c.status == "DISPROVEN" for c in claim_results):
                rejection["POSITIVE_DISPROVEN"] = (
                    rejection.get("POSITIVE_DISPROVEN", 0) + 1
                )
                continue
            if any(c.status == "UNKNOWN" for c in claim_results):
                saw_unknown = True
                rejection["POSITIVE_UNKNOWN"] = rejection.get("POSITIVE_UNKNOWN", 0) + 1
                continue
            if any(c.status == "NOT_APPLICABLE" for c in claim_results if c.required):
                rejection["NOT_APPLICABLE"] = rejection.get("NOT_APPLICABLE", 0) + 1
                continue
            if groups:
                failed_group = any(
                    not any(
                        next((x for x in claim_results if x.claim_id == c.id), None)
                        and next(x for x in claim_results if x.claim_id == c.id).status
                        == "PROVEN"
                        for c in group
                    )
                    for group in groups
                )
                if failed_group:
                    rejection["CLAIM_GROUP"] = rejection.get("CLAIM_GROUP", 0) + 1
                    continue
            if len(matched) < self.max_witness_alternatives:
                matched.append(binding)

        if matched:
            binding = matched[0]
            cr = [self._claim_with_binding(c, binding, slots) for c in required_claims]
            xr = [self._claim_with_binding(c, binding, slots) for c in counters]
            return WitnessResult(
                witness.id,
                "MATCH",
                binding,
                cr,
                xr,
                "coherent witness satisfied all required evidence",
                combinations,
                matched,
                rejection,
                search_complete=(combinations >= total),
            )
        if best is not None:
            binding, cr, xr = best
            required_disproven = any(c.required and c.status == "DISPROVEN" for c in cr)
            required_unknown = any(c.required and c.status == "UNKNOWN" for c in cr)
            if required_disproven:
                status = "NO_MATCH"
            elif saw_unknown or required_unknown:
                status = self._unknown_status(pattern)
            else:
                status = "NO_MATCH"
            return WitnessResult(
                witness.id,
                status,
                binding,
                cr,
                xr,
                "no binding satisfied the complete positive evidence",
                combinations,
                [],
                rejection,
                search_complete=(combinations >= total),
            )
        return WitnessResult(
            witness.id,
            "NO_MATCH",
            {},
            [],
            [],
            "no candidate binding survived",
            combinations,
            [],
            rejection,
            search_complete=True,
        )

    @staticmethod
    def _resolve_operand(node: Node | None, operand: dict[str, Any]) -> Any:
        if node is None:
            return None
        prop = str(operand.get("property", "derived.numeric_value"))
        return get_property(node, prop, None)

    def _range_operand(
        self, operand: dict[str, Any] | None, binding: dict[str, str]
    ) -> dict[str, Any] | None:
        if not operand:
            return None
        if "value" in operand:
            v = operand["value"]
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return {"lower": v, "upper": v, "proof": "LITERAL_OPERAND"}
            return None
        if "slot" not in operand:
            return None
        node = self.graph.nodes.get(binding.get(str(operand["slot"]), ""))
        if not node:
            return None
        prop = str(operand.get("property", "derived.range"))
        val = get_property(node, prop, None)
        if isinstance(val, dict) and "lower" in val and "upper" in val:
            lo, hi = val.get("lower"), val.get("upper")
            if (
                isinstance(lo, (int, float))
                and isinstance(hi, (int, float))
                and lo <= hi
            ):
                return {"lower": lo, "upper": hi, "proof": val.get("proof", "EXPLICIT")}
        if prop == "derived.range" or prop == "derived.numeric_range":
            return node_value_range(self.graph, node.id)
        if (
            prop == "derived.memory_capacity"
            and get_property(node, prop, None) is not None
        ):
            x = get_property(node, prop, None)
            if isinstance(x, (int, float)):
                unit = str(
                    get_property(node, "derived.capacity_unit", "UNKNOWN")
                ).upper()
                if unit != "BYTES":
                    return None
                return {"lower": x, "upper": x, "proof": "BYTE_CAPACITY"}
        if prop in {
            "derived.length",
            "derived.memory_capacity",
            "derived.numeric_value",
        }:
            x = get_property(node, prop, None)
            if isinstance(x, (int, float)) and not isinstance(x, bool):
                return {"lower": x, "upper": x, "proof": "EXACT_PROPERTY"}
        return node_value_range(self.graph, node.id)

    @staticmethod
    def _range_relation(a: dict[str, Any], b: dict[str, Any], op: str) -> str:
        al, au, bl, bu = a["lower"], a["upper"], b["lower"], b["upper"]
        if op == ">":
            if al > bu:
                return "PROVEN"
            if au <= bl:
                return "DISPROVEN"
        elif op == ">=":
            if al >= bu:
                return "PROVEN"
            if au < bl:
                return "DISPROVEN"
        elif op == "<":
            if au < bl:
                return "PROVEN"
            if al >= bu:
                return "DISPROVEN"
        elif op == "<=":
            if au <= bl:
                return "PROVEN"
            if al > bu:
                return "DISPROVEN"
        elif op == "==":
            if al == au == bl == bu:
                return "PROVEN"
            if au < bl or bu < al:
                return "DISPROVEN"
        elif op == "!=":
            if au < bl or bu < al:
                return "PROVEN"
            if al == au == bl == bu:
                return "DISPROVEN"
        return "UNKNOWN"

    def _relation_candidates(
        self,
        c: Claim,
        binding: dict[str, str],
        source_default: list[str] | None = None,
        target_default: list[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        if c.source:
            sources = [binding[c.source]] if binding.get(c.source) else []
        elif c.source_selector:
            sources = self._candidate_ids(c.source_selector)
        else:
            sources = list(source_default or [])
        if c.target:
            targets = [binding[c.target]] if binding.get(c.target) else []
        elif c.target_selector:
            targets = self._candidate_ids(c.target_selector)
        else:
            targets = list(target_default or [])
        return sources, targets

    def _claim_with_binding(
        self, c: Claim, binding: dict[str, str], slots: dict[str, list[str]]
    ) -> ClaimResult:
        if c.kind in {"relation_any", "relation_none"}:
            sources, targets = self._relation_candidates(c, binding)
            if not sources or not targets:
                complete = self._is_complete(self.graph)
                if c.kind == "relation_none":
                    status = "PROVEN" if complete else "UNKNOWN"
                    reason = (
                        "no relation candidates exist in complete graph"
                        if complete
                        else "relation absence cannot be established on incomplete graph"
                    )
                else:
                    status = "DISPROVEN" if complete else "UNKNOWN"
                    reason = (
                        "no relation candidates exist in complete graph"
                        if complete
                        else "relation cannot be established on incomplete graph"
                    )
                return ClaimResult(
                    c.id,
                    c.kind,
                    status,
                    c.required,
                    c.description,
                    [],
                    reason,
                    c.proof_level,
                )
            proven_pairs: list[dict[str, Any]] = []
            saw_unknown = False
            for src, dst in itertools.product(sources[:100], targets[:100]):
                probe = Claim(
                    id=c.id,
                    kind="relation",
                    required=c.required,
                    description=c.description,
                    source="__src",
                    target="__dst",
                    edge_types=c.edge_types,
                    relation=c.relation,
                    direction=c.direction,
                    max_hops=c.max_hops,
                    edge_equals=c.edge_equals,
                    edge_any_of=c.edge_any_of,
                    proof_level=c.proof_level,
                )
                r = self._claim_with_binding(probe, {"__src": src, "__dst": dst}, slots)
                if r.status == "PROVEN":
                    proven_pairs.extend(r.matches[:10])
                    if c.kind == "relation_any":
                        return ClaimResult(
                            c.id,
                            c.kind,
                            "PROVEN",
                            c.required,
                            c.description,
                            proven_pairs,
                            "at least one relation exists",
                            c.proof_level,
                        )
                elif r.status == "UNKNOWN":
                    saw_unknown = True
            if c.kind == "relation_none":
                if proven_pairs:
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "DISPROVEN",
                        c.required,
                        c.description,
                        proven_pairs,
                        "forbidden relation exists",
                        c.proof_level,
                    )
                if saw_unknown or not self._is_complete(self.graph):
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "UNKNOWN",
                        c.required,
                        c.description,
                        [],
                        "absence of relation cannot be proven",
                        c.proof_level,
                    )
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [],
                    "no matching relation exists",
                    c.proof_level,
                )
            if saw_unknown or not self._is_complete(self.graph):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "relation cannot be proven",
                    c.proof_level,
                )
            return ClaimResult(
                c.id,
                c.kind,
                "DISPROVEN",
                c.required,
                c.description,
                [],
                "no matching relation exists",
                c.proof_level,
            )

        if c.kind == "node":
            nid = binding.get(c.slot or "")
            node = self.graph.nodes.get(nid or "")
            if not node:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "bound node unavailable",
                    c.proof_level,
                )
            ok = c.selector is None or _selector_matches(node, c.selector)
            return ClaimResult(
                c.id,
                c.kind,
                "PROVEN" if ok else "DISPROVEN",
                c.required,
                c.description,
                [_node_match_record(node)],
                "node satisfies selector" if ok else "bound node contradicts selector",
                c.proof_level,
            )

        if c.kind == "node_absence":
            if not self._is_complete(self.graph):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "absence cannot be proven on an incomplete graph",
                    c.proof_level,
                )
            ids = self._candidate_ids(c.selector)
            return ClaimResult(
                c.id,
                c.kind,
                "PROVEN" if not ids else "DISPROVEN",
                c.required,
                c.description,
                [{"node": x} for x in ids[:100]],
                "no matching node" if not ids else "matching node exists",
                c.proof_level,
            )

        if c.kind == "property":
            nid = binding.get(c.slot or "")
            node = self.graph.nodes.get(nid or "") if nid else None
            if not node:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "bound node unavailable",
                    c.proof_level,
                )
            ok, missing = _properties_match(
                node, c.equals, c.any_of, c.properties_present
            )
            if ok:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [_node_match_record(node)],
                    "properties satisfied",
                    c.proof_level,
                )
            return ClaimResult(
                c.id,
                c.kind,
                "UNKNOWN" if missing else "DISPROVEN",
                c.required,
                c.description,
                [{"node": node.id}],
                "missing properties: " + ", ".join(missing)
                if missing
                else "known value contradicts property",
                c.proof_level,
            )

        if c.kind in {"path", "path_absence", "relation"}:
            src = binding.get(c.source or "")
            dst = binding.get(c.target or "")
            if not src or not dst:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "source/target binding missing",
                    c.proof_level,
                )
            # Joern can encode method context on the target node without a METHOD-to-CALL CONTAINS edge.
            if str(c.relation or "").upper() == "PARENT_METHOD":
                node = self.graph.nodes.get(dst)
                parent = get_property(node, "derived.parent_method_node", None)
                if parent is None:
                    parent = get_property(node, "parent_method_node", None)
                if parent is not None and str(parent) == str(src):
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "PROVEN",
                        c.required,
                        c.description,
                        [{"node": dst, "parent_method": src}],
                        "target node has the bound method as structural parent",
                        c.proof_level,
                    )
                status = "DISPROVEN" if self._is_complete(self.graph) else "UNKNOWN"
                return ClaimResult(
                    c.id,
                    c.kind,
                    status,
                    c.required,
                    c.description,
                    [],
                    "target parent method differs or is absent"
                    if status == "DISPROVEN"
                    else "parent method relation unavailable on incomplete graph",
                    c.proof_level,
                )
            edge_types = semantic_edge_types(c.relation, c.edge_types)
            paths, truncated = self.graph.find_paths_bounded(
                [src],
                {dst},
                edge_types,
                min(int(c.max_hops), self.hard_max_hops),
                c.direction,
                100,
                max_states=50_000,
            )
            if c.kind in {"path", "relation"}:
                if paths:
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "PROVEN",
                        c.required,
                        c.description,
                        [{"path": p} for p in paths],
                        f"{len(paths)} path(s) found",
                        c.proof_level,
                    )
                if truncated:
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "UNKNOWN",
                        c.required,
                        c.description,
                        [],
                        "path search budget exhausted; absence is not provable",
                        c.proof_level,
                    )
                status = "DISPROVEN" if self._is_complete(self.graph) else "UNKNOWN"
                return ClaimResult(
                    c.id,
                    c.kind,
                    status,
                    c.required,
                    c.description,
                    [],
                    "relation path not found in complete graph"
                    if status == "DISPROVEN"
                    else "relation path not found but absence is not provable on incomplete graph",
                    c.proof_level,
                )
            if truncated:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [{"path": p} for p in paths],
                    "path search budget exhausted; absence is not provable",
                    c.proof_level,
                )
            if not self._is_complete(self.graph):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [{"path": p} for p in paths],
                    "absence requires a complete graph",
                    c.proof_level,
                )
            return ClaimResult(
                c.id,
                c.kind,
                "DISPROVEN" if paths else "PROVEN",
                c.required,
                c.description,
                [{"path": p} for p in paths],
                "forbidden relation exists"
                if paths
                else "no forbidden relation exists",
                c.proof_level,
            )

        if c.kind == "edge":
            src = binding.get(c.source or "")
            dst = binding.get(c.target or "")
            edge_types = semantic_edge_types(c.relation, c.edge_types)
            if not src or not dst:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "source/target binding missing",
                    c.proof_level,
                )
            if c.direction == "out":
                edges = self.graph.matching_edges(src, dst, edge_types)
            elif c.direction == "in":
                edges = self.graph.matching_edges(dst, src, edge_types)
            else:
                edges = self.graph.matching_edges(src, dst, edge_types, True)
            if c.edge_equals or c.edge_any_of:
                filtered = []
                for e in edges:
                    ok, _ = _edge_properties_match(e, c.edge_equals, c.edge_any_of)
                    if ok:
                        filtered.append(e)
                edges = filtered
            if edges:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [
                        {
                            "edge": e.id,
                            "source": e.source,
                            "target": e.target,
                            "type": e.type,
                            "properties": e.properties,
                        }
                        for e in edges[:100]
                    ],
                    "matching edge exists",
                    c.proof_level,
                )
            status = "DISPROVEN" if self._is_complete(self.graph) else "UNKNOWN"
            return ClaimResult(
                c.id,
                c.kind,
                status,
                c.required,
                c.description,
                [],
                "edge not found in complete graph"
                if status == "DISPROVEN"
                else "edge not found but absence is not provable on incomplete graph",
                c.proof_level,
            )

        if c.kind == "compare":
            left = self._operand(c.left, binding)
            right = self._operand(c.right, binding)
            if left is None or right is None:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    f"unresolved operands: {left!r}, {right!r}",
                    c.proof_level,
                )
            ok = self._compare(left, right, c.operator or "==")
            return ClaimResult(
                c.id,
                c.kind,
                "PROVEN" if ok else "DISPROVEN",
                c.required,
                c.description,
                [{"left": left, "operator": c.operator, "right": right}],
                f"{left!r} {c.operator} {right!r} = {ok}",
                c.proof_level,
            )

        if c.kind == "semantic":
            nid = binding.get(c.slot or "")
            node = self.graph.nodes.get(nid or "") if nid else None
            if not node:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "bound node unavailable",
                    c.proof_level,
                )
            props = c.equals or {}
            ok, missing = _properties_match(node, props, c.any_of, c.properties_present)
            if ok:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [_node_match_record(node)],
                    "semantic facts satisfied",
                    c.proof_level,
                )
            return ClaimResult(
                c.id,
                c.kind,
                "UNKNOWN" if missing else "DISPROVEN",
                c.required,
                c.description,
                [_node_match_record(node)],
                "missing semantic facts: " + ", ".join(missing)
                if missing
                else "semantic fact contradicts claim",
                c.proof_level,
            )

        if c.kind == "same_object":
            a = self.graph.nodes.get(binding.get(c.source or "", ""))
            b = self.graph.nodes.get(binding.get(c.target or "", ""))
            if not a or not b:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "source/target binding missing",
                    c.proof_level,
                )
            ao = get_property(a, "derived.object_id", None)
            if ao is None:
                ao = get_property(a, "object_id", None)
            bo = get_property(b, "derived.object_id", None)
            if bo is None:
                bo = get_property(b, "object_id", None)
            ap = str(
                get_property(
                    a, "derived.object_id_proof", get_property(a, "object_id_proof", "")
                )
            )
            bp = str(
                get_property(
                    b, "derived.object_id_proof", get_property(b, "object_id_proof", "")
                )
            )
            strong = {"EXPLICIT", "DIRECT_REF", "EXPLICIT_ALIAS"}
            if ao is not None and bo is not None and ap in strong and bp in strong:
                status = "PROVEN" if str(ao) == str(bo) else "DISPROVEN"
                return ClaimResult(
                    c.id,
                    c.kind,
                    status,
                    c.required,
                    c.description,
                    [
                        {
                            "source_object": ao,
                            "target_object": bo,
                            "source_proof": ap,
                            "target_proof": bp,
                        }
                    ],
                    f"strong object_id equality = {str(ao) == str(bo)}",
                    c.proof_level,
                )
            # Require a direct reference between the bound expressions or objects.
            if self.graph.edge_exists(a.id, b.id, {"REF"}, True):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [{"source": a.id, "target": b.id}],
                    "direct REF establishes object resolution",
                    c.proof_level,
                )
            # Names alone cannot prove object identity because of shadowing and aliasing.
            return ClaimResult(
                c.id,
                c.kind,
                "UNKNOWN",
                c.required,
                c.description,
                [],
                "object identity lacks strong proof",
                c.proof_level,
            )

        if c.kind == "range_compare":
            left = self._range_operand(c.left, binding)
            right = self._range_operand(c.right, binding)
            if left is None or right is None:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "unresolved operand range",
                    c.proof_level,
                )
            status = self._range_relation(left, right, c.operator or "==")
            return ClaimResult(
                c.id,
                c.kind,
                status,
                c.required,
                c.description,
                [{"left": left, "operator": c.operator, "right": right}],
                f"range relation = {status}",
                c.proof_level,
            )

        if c.kind == "cardinality":
            count = (
                len(slots.get(c.slot or "", []))
                if c.slot
                else len(self._candidate_ids(c.selector))
            )
            complete = self._is_complete(self.graph)
            if not complete and c.max_count is not None:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [{"count": count}],
                    f"upper-bound cardinality cannot be proven on incomplete graph; observed count={count}",
                    c.proof_level,
                )
            if not complete and c.min_count is not None and count < c.min_count:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [{"count": count}],
                    f"minimum cardinality not established on incomplete graph; observed count={count}",
                    c.proof_level,
                )
            ok = (c.min_count is None or count >= c.min_count) and (
                c.max_count is None or count <= c.max_count
            )
            return ClaimResult(
                c.id,
                c.kind,
                "PROVEN" if ok else "DISPROVEN",
                c.required,
                c.description,
                [{"count": count}],
                f"count={count}",
                c.proof_level,
            )

        return ClaimResult(
            c.id,
            c.kind,
            "UNKNOWN",
            c.required,
            c.description,
            [],
            "unsupported claim kind",
            c.proof_level,
        )

    def _claim(self, c: Claim, slots: dict[str, list[str]]) -> ClaimResult:
        if c.kind in {"node", "node_absence"}:
            ids = (
                slots.get(c.slot or "", [])
                if c.slot
                else self._candidate_ids(c.selector)
            )
            if c.selector:
                ids = [
                    x for x in ids if _selector_matches(self.graph.nodes[x], c.selector)
                ]
            if c.kind == "node":
                if ids:
                    return ClaimResult(
                        c.id,
                        c.kind,
                        "PROVEN",
                        c.required,
                        c.description,
                        [{"node": x} for x in ids[:100]],
                        f"{len(ids)} matching node(s)",
                        c.proof_level,
                    )
                status = "DISPROVEN" if self._is_complete(self.graph) else "UNKNOWN"
                return ClaimResult(
                    c.id,
                    c.kind,
                    status,
                    c.required,
                    c.description,
                    [],
                    "no matching node in complete graph"
                    if status == "DISPROVEN"
                    else "no matching node but absence is not provable on incomplete graph",
                    c.proof_level,
                )
            if not self._is_complete(self.graph):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "absence cannot be proven on incomplete graph",
                    c.proof_level,
                )
            return ClaimResult(
                c.id,
                c.kind,
                "PROVEN" if not ids else "DISPROVEN",
                c.required,
                c.description,
                [{"node": x} for x in ids[:100]],
                "absent" if not ids else "present",
                c.proof_level,
            )

        if c.kind == "property":
            candidates = slots.get(c.slot or "", [])
            matches = [
                nid
                for nid in candidates
                if _properties_match(
                    self.graph.nodes[nid], c.equals, c.any_of, c.properties_present
                )[0]
            ]
            if matches:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "PROVEN",
                    c.required,
                    c.description,
                    [{"node": x} for x in matches[:100]],
                    f"{len(matches)} matching node(s)",
                    c.proof_level,
                )
            if not candidates:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "no bound candidates",
                    c.proof_level,
                )
            # Conflicting known values disprove the claim.
            return ClaimResult(
                c.id,
                c.kind,
                "DISPROVEN" if self._is_complete(self.graph) else "UNKNOWN",
                c.required,
                c.description,
                [],
                "no candidate satisfies the property"
                if self._is_complete(self.graph)
                else "property cannot be disproven on incomplete graph",
                c.proof_level,
            )

        if c.kind == "compare":
            involved = [
                str(op["slot"])
                for op in (c.left, c.right)
                if isinstance(op, dict) and op.get("slot")
            ]
            if not involved:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "compare has no slot-bound operands",
                    c.proof_level,
                )
            arrays = [slots.get(s, [])[:100] for s in involved]
            if any(not arr for arr in arrays):
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "compare has an empty operand slot",
                    c.proof_level,
                )
            results = [
                self._claim_with_binding(c, dict(zip(involved, vals)), slots)
                for vals in itertools.product(*arrays)
            ]
            proven = next((r for r in results if r.status == "PROVEN"), None)
            if proven:
                return proven
            disproven = next((r for r in results if r.status == "DISPROVEN"), None)
            return disproven or ClaimResult(
                c.id,
                c.kind,
                "UNKNOWN",
                c.required,
                c.description,
                [],
                "no resolvable operand binding",
                c.proof_level,
            )

        if c.kind in {"relation_any", "relation_none"}:
            return self._claim_with_binding(c, {}, slots)

        if c.kind in {"path", "path_absence", "edge", "relation"}:
            if not c.source or not c.target:
                return ClaimResult(
                    c.id,
                    c.kind,
                    "UNKNOWN",
                    c.required,
                    c.description,
                    [],
                    "relation claim needs source/target",
                    c.proof_level,
                )
            saw_unknown = False
            for src, dst in itertools.product(
                slots.get(c.source, [])[:100], slots.get(c.target, [])[:100]
            ):
                r = self._claim_with_binding(c, {c.source: src, c.target: dst}, slots)
                if r.status == "PROVEN":
                    return r
                saw_unknown = saw_unknown or r.status == "UNKNOWN"
                if c.kind == "path_absence" and r.status == "DISPROVEN":
                    return r
            if saw_unknown or not slots.get(c.source) or not slots.get(c.target):
                status = "UNKNOWN"
            else:
                status = "DISPROVEN" if c.kind != "path_absence" else "PROVEN"
            return ClaimResult(
                c.id,
                c.kind,
                status,
                c.required,
                c.description,
                [],
                "no relation proven"
                if c.kind != "path_absence"
                else "no forbidden relation exists",
                c.proof_level,
            )

        if c.kind == "cardinality":
            return self._claim_with_binding(c, {}, slots)
        return ClaimResult(
            c.id,
            c.kind,
            "UNKNOWN",
            c.required,
            c.description,
            [],
            "unsupported global claim",
            c.proof_level,
        )

    def _candidate_ids(self, selector: Selector | None) -> list[str]:
        if selector is None:
            return []
        return [
            n.id for n in self.graph.nodes.values() if _selector_matches(n, selector)
        ]

    def _operand(self, operand: dict[str, Any] | None, binding: dict[str, str]) -> Any:
        if not operand:
            return None
        if "value" in operand:
            return operand["value"]
        if "slot" in operand:
            node = self.graph.nodes.get(binding.get(str(operand["slot"]), ""))
            if not node:
                return None
            return get_property(
                node, str(operand.get("property", "derived.numeric_value")), None
            )
        return None

    def _compare(self, a: Any, b: Any, op: str) -> bool:
        try:
            if op == "==":
                return _value_equal(a, b)
            if op == "!=":
                return not _value_equal(a, b)
            if op == "<":
                return a < b
            if op == "<=":
                return a <= b
            if op == ">":
                return a > b
            if op == ">=":
                return a >= b
            if op == "in":
                return a in b
            if op == "not_in":
                return a not in b
            if op == "contains":
                return b in a
            if op == "not_contains":
                return b not in a
        except Exception:
            return False
        return False
