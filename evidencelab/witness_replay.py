from __future__ import annotations

import itertools
from typing import Any
import copy

from .models import Graph
from .semantics import get_property, semantic_edge_types, node_value_range
from .canonical import canonicalize_graph
from .spec import Pattern, Claim, Selector
from .matcher import _selector_matches, _properties_match, _edge_properties_match


class WitnessReplay:
    """Independent, fixed-binding witness replay.

    Unlike the search matcher, replay does not enumerate slot candidates and does not
    choose a witness. It checks only the concrete binding already emitted in a report.
    This makes report corruption, stale bindings and mismatched proof states detectable.
    """

    def __init__(self, graph: Graph, pattern: Pattern):
        # Preserve artifact identity while deriving the canonical properties used by matching.
        self.raw_graph_digest = graph.digest()
        self.graph = canonicalize_graph(graph)
        self.pattern = pattern

    def _complete(self) -> bool:
        return (self.graph.metadata.get("parse_health") or "OK") == "OK" and (
            self.graph.metadata.get("completeness") or "declared"
        ) in {"declared", "full_export"}

    def _bound_node(self, binding: dict[str, str], slot: str | None):
        if not slot:
            return None
        return self.graph.nodes.get(str(binding.get(slot, "")))

    def _relation(
        self, c: Claim, binding: dict[str, str]
    ) -> tuple[str, list[Any], str]:
        src = self._bound_node(binding, c.source)
        dst = self._bound_node(binding, c.target)
        if src is None or dst is None:
            return "UNKNOWN", [], "source/target binding missing"
        if str(c.relation or "").upper() == "PARENT_METHOD":
            parent = get_property(
                dst,
                "derived.parent_method_node",
                get_property(dst, "parent_method_node", None),
            )
            if parent is None:
                return (
                    ("UNKNOWN" if not self._complete() else "DISPROVEN"),
                    [],
                    "parent method identity unavailable",
                )
            return (
                (
                    "PROVEN",
                    [{"node": dst.id, "parent_method": str(parent)}],
                    "parent method matches",
                )
                if str(parent) == str(src.id)
                else ("DISPROVEN", [], "parent method differs")
            )
        types = semantic_edge_types(c.relation, c.edge_types)
        paths = self.graph.find_paths(
            [src.id], {dst.id}, types, c.max_hops, c.direction, 100
        )
        if paths:
            return "PROVEN", [{"path": p} for p in paths], "path exists"
        return (("UNKNOWN" if not self._complete() else "DISPROVEN"), [], "path absent")

    def _compare(self, a: Any, b: Any, op: str) -> str:
        if a is None or b is None:
            return "UNKNOWN"
        try:
            if op == "==":
                return "PROVEN" if a == b else "DISPROVEN"
            if op == "!=":
                return "PROVEN" if a != b else "DISPROVEN"
            if op == "<":
                return "PROVEN" if a < b else "DISPROVEN"
            if op == "<=":
                return "PROVEN" if a <= b else "DISPROVEN"
            if op == ">":
                return "PROVEN" if a > b else "DISPROVEN"
            if op == ">=":
                return "PROVEN" if a >= b else "DISPROVEN"
            if op == "in":
                return "PROVEN" if a in b else "DISPROVEN"
            if op == "not_in":
                return "PROVEN" if a not in b else "DISPROVEN"
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"

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
        slot = operand.get("slot")
        if slot is None:
            return None
        node = self._bound_node(binding, str(slot))
        if node is None:
            return None
        prop = str(operand.get("property", "derived.range"))
        value = get_property(node, prop, None)
        if isinstance(value, dict) and "lower" in value and "upper" in value:
            lo, hi = value.get("lower"), value.get("upper")
            if (
                isinstance(lo, (int, float))
                and isinstance(hi, (int, float))
                and lo <= hi
            ):
                return {
                    "lower": lo,
                    "upper": hi,
                    "proof": value.get("proof", "EXPLICIT"),
                }
        # Keep replay independent of candidate enumeration and support top-level or nested derived values.
        direct = None
        if isinstance(node.properties, dict):
            direct = node.properties.get(prop)
            if direct is None and prop.startswith("derived."):
                derived = node.properties.get("derived")
                if isinstance(derived, dict):
                    direct = derived.get(prop.split(".", 1)[1])
        if isinstance(direct, dict) and "lower" in direct and "upper" in direct:
            lo, hi = direct.get("lower"), direct.get("upper")
            if (
                isinstance(lo, (int, float))
                and isinstance(hi, (int, float))
                and lo <= hi
            ):
                return {
                    "lower": lo,
                    "upper": hi,
                    "proof": direct.get("proof", "EXPLICIT"),
                }
        if isinstance(direct, (int, float)) and not isinstance(direct, bool):
            return {"lower": direct, "upper": direct, "proof": "EXACT_PROPERTY"}
        # Use canonical semantic derivation as the fallback for numeric and range values.
        r = node_value_range(self.graph, node.id)
        if r:
            return r
        return None

    @staticmethod
    def _range_compare(
        a: dict[str, Any] | None, b: dict[str, Any] | None, op: str
    ) -> str:
        if not a or not b:
            return "UNKNOWN"
        al, au, bl, bu = a["lower"], a["upper"], b["lower"], b["upper"]
        try:
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
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"

    def _operand(self, operand: dict[str, Any] | None, binding: dict[str, str]) -> Any:
        if not operand:
            return None
        if "value" in operand:
            return operand["value"]
        if "slot" in operand:
            node = self._bound_node(binding, str(operand["slot"]))
            if node is None:
                return None
            value = get_property(
                node, str(operand.get("property", "derived.numeric_value")), None
            )
            if isinstance(value, str):
                s = value.strip()
                try:
                    return int(s, 0)
                except Exception:
                    try:
                        return float(s)
                    except Exception:
                        return value
            return value
        return None

    def claim(
        self,
        c: Claim,
        binding: dict[str, str],
        expected_matches: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        expected_matches = expected_matches or []
        if c.kind == "node":
            node = self._bound_node(binding, c.slot)
            if node is None:
                return {"status": "UNKNOWN", "matches": []}
            ok = c.selector is None or _selector_matches(node, c.selector)
            return {
                "status": "PROVEN" if ok else "DISPROVEN",
                "matches": [{"node": node.id}] if ok else [],
            }
        if c.kind == "property" or c.kind == "semantic":
            node = self._bound_node(binding, c.slot)
            if node is None:
                return {"status": "UNKNOWN", "matches": []}
            ok, missing = _properties_match(
                node, c.equals, c.any_of, c.properties_present
            )
            status = "PROVEN" if ok else ("UNKNOWN" if missing else "DISPROVEN")
            return {
                "status": status,
                "matches": [{"node": node.id}],
                "missing": missing,
            }
        if c.kind in {"path", "relation", "path_absence"}:
            status, matches, explanation = self._relation(c, binding)
            if c.kind == "path_absence":
                status = (
                    "UNKNOWN"
                    if not self._complete() and status != "PROVEN"
                    else ("DISPROVEN" if status == "PROVEN" else "PROVEN")
                )
            return {"status": status, "matches": matches, "explanation": explanation}
        if c.kind in {"relation_any", "relation_none"}:
            sources = (
                [binding[c.source]] if c.source and binding.get(c.source) else None
            )
            targets = (
                [binding[c.target]] if c.target and binding.get(c.target) else None
            )
            if sources is None:
                if c.source_selector is not None:
                    sources = [
                        n.id
                        for n in self.graph.nodes.values()
                        if _selector_matches(n, c.source_selector)
                    ]
                else:
                    sources = []
            if targets is None:
                if c.target_selector is not None:
                    targets = [
                        n.id
                        for n in self.graph.nodes.values()
                        if _selector_matches(n, c.target_selector)
                    ]
                else:
                    targets = []
            if not sources or not targets:
                if c.kind == "relation_any":
                    return {
                        "status": "DISPROVEN" if self._complete() else "UNKNOWN",
                        "matches": [],
                        "explanation": "no relation candidates exist",
                    }
                return {
                    "status": "PROVEN" if self._complete() else "UNKNOWN",
                    "matches": [],
                    "explanation": "no forbidden relation candidates exist",
                }
            proven = []
            unknown = False
            for src_id in sources[:100]:
                for dst_id in targets[:100]:
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
                        proof_level=c.proof_level,
                    )
                    rr = self._relation(
                        probe, {"__src": str(src_id), "__dst": str(dst_id)}
                    )
                    if rr[0] == "PROVEN":
                        proven.extend(rr[1][:10])
                    elif rr[0] == "UNKNOWN":
                        unknown = True
            if c.kind == "relation_any":
                if proven:
                    return {
                        "status": "PROVEN",
                        "matches": proven[:20],
                        "explanation": "at least one relation exists",
                    }
                if unknown:
                    return {
                        "status": "UNKNOWN",
                        "matches": [],
                        "explanation": "relation absence/presence cannot be resolved",
                    }
                return {
                    "status": "DISPROVEN",
                    "matches": [],
                    "explanation": "no matching relation exists",
                }
            if proven:
                return {
                    "status": "DISPROVEN",
                    "matches": proven[:20],
                    "explanation": "forbidden relation exists",
                }
            if unknown:
                return {
                    "status": "UNKNOWN",
                    "matches": [],
                    "explanation": "forbidden relation absence cannot be proven",
                }
            return {
                "status": "PROVEN",
                "matches": [],
                "explanation": "no forbidden relation exists",
            }
        if c.kind == "edge":
            src = self._bound_node(binding, c.source)
            dst = self._bound_node(binding, c.target)
            if not src or not dst:
                return {"status": "UNKNOWN", "matches": []}
            types = semantic_edge_types(c.relation, c.edge_types)
            edges = (
                self.graph.matching_edges(
                    src.id, dst.id, types, c.direction == "either"
                )
                if c.direction != "in"
                else self.graph.matching_edges(dst.id, src.id, types)
            )
            if c.edge_equals or c.edge_any_of:
                edges = [
                    e
                    for e in edges
                    if _edge_properties_match(e, c.edge_equals, c.edge_any_of)[0]
                ]
            return {
                "status": "PROVEN"
                if edges
                else ("UNKNOWN" if not self._complete() else "DISPROVEN"),
                "matches": [
                    {
                        "edge": e.id,
                        "source": e.source,
                        "target": e.target,
                        "type": e.type,
                    }
                    for e in edges
                ],
            }
        if c.kind == "same_object":
            a = self._bound_node(binding, c.source)
            b = self._bound_node(binding, c.target)
            if not a or not b:
                return {"status": "UNKNOWN", "matches": []}
            ao = get_property(
                a, "derived.object_id", get_property(a, "object_id", None)
            )
            bo = get_property(
                b, "derived.object_id", get_property(b, "object_id", None)
            )
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
                return {
                    "status": "PROVEN" if str(ao) == str(bo) else "DISPROVEN",
                    "matches": [{"source_object": ao, "target_object": bo}],
                }
            if self.graph.edge_exists(a.id, b.id, {"REF"}, True):
                return {
                    "status": "PROVEN",
                    "matches": [{"source": a.id, "target": b.id}],
                }
            return {"status": "UNKNOWN", "matches": []}
        if c.kind == "range_compare":
            left = self._range_operand(c.left, binding)
            right = self._range_operand(c.right, binding)
            status = self._range_compare(left, right, c.operator or "==")
            return {
                "status": status,
                "matches": [{"left": left, "operator": c.operator, "right": right}],
            }
        if c.kind == "compare":
            left = self._operand(c.left, binding)
            right = self._operand(c.right, binding)
            status = self._compare(left, right, c.operator or "==")
            return {
                "status": status,
                "matches": [{"left": left, "operator": c.operator, "right": right}],
            }
        if c.kind == "cardinality":
            count = len(
                [
                    n
                    for n in self.graph.nodes.values()
                    if c.selector and _selector_matches(n, c.selector)
                ]
            )
            if c.slot:
                node_ids = {binding.get(c.slot)} if binding.get(c.slot) else set()
                count = len(node_ids)
            ok = (c.min_count is None or count >= c.min_count) and (
                c.max_count is None or count <= c.max_count
            )
            if not self._complete() and c.max_count is not None:
                return {"status": "UNKNOWN", "matches": [{"count": count}]}
            return {
                "status": "PROVEN" if ok else "DISPROVEN",
                "matches": [{"count": count}],
            }
        return {"status": "UNKNOWN", "matches": []}

    def validate(self, match: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        validated = 0
        pattern_claims = {
            c.id: c for c in self.pattern.claims + self.pattern.counter_claims
        }
        for witness in match.get("witnesses", []) or []:
            binding = {
                str(k): str(v) for k, v in (witness.get("bindings") or {}).items()
            }
            for sid, nid in binding.items():
                if sid not in self.pattern.slots:
                    errors.append(f"{witness.get('witness_id')}: unknown slot {sid}")
                elif nid not in self.graph.nodes:
                    errors.append(
                        f"{witness.get('witness_id')}: bound node missing {nid}"
                    )
            for cr in (witness.get("claims") or []) + (
                witness.get("counter_evidence") or []
            ):
                cid = str(cr.get("claim_id"))
                c = pattern_claims.get(cid)
                if not c:
                    errors.append(f"unknown claim id {cid}")
                    continue
                replay = self.claim(c, binding, cr.get("matches"))
                recorded = str(cr.get("status", "UNKNOWN"))
                if replay["status"] != recorded:
                    errors.append(
                        f"{witness.get('witness_id')}/{cid}: recorded {recorded}, replay {replay['status']}"
                    )
                validated += 1
        trace = match.get("evidence_trace") or {}
        if trace.get("graph_digest") and trace["graph_digest"] != self.raw_graph_digest:
            errors.append("graph digest mismatch")
        return {
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
            "validation_mode": "fixed-binding-semantic-replay",
            "claims_replayed": validated,
            "graph_digest": self.raw_graph_digest,
        }
