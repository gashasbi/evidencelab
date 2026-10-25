from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
from typing import Any

from . import SCHEMA_VERSION
from .models import Edge, Graph, Node, norm, stable_json
from .semantics import _num, enrich_graph, semantic_edge_types

CANONICAL_GRAPH_FORMAT = "evidencelab-canonical-graph"
CANONICAL_GRAPH_VERSION = "1.0"

SEMANTIC_FINGERPRINT_ALGORITHM = "canonical-node/edge semantic aggregate sha256 v4"

CANONICAL_NODE_ALIASES = {
    "METHOD_PARAMETER_IN": "PARAMETER",
    "METHOD_PARAMETER_OUT": "PARAMETER",
    "METHOD_RETURN": "RETURN",
    "METHOD": "METHOD",
    "CALL": "CALL",
    "CONTROL_STRUCTURE": "CONTROL",
    "BLOCK": "BLOCK",
    "LOCAL": "LOCAL",
    "IDENTIFIER": "IDENTIFIER",
    "LITERAL": "LITERAL",
    "MEMBER": "FIELD",
    "FIELD_IDENTIFIER": "FIELD",
    "TYPE_DECL": "TYPE",
    "TYPE": "TYPE",
    "FILE": "FILE",
    "NAMESPACE_BLOCK": "NAMESPACE",
    "RETURN": "RETURN",
}

CANONICAL_EDGE_ALIASES = {
    "REACHING_DEF": "DATA_FLOW",
    "DATA_FLOW": "DATA_FLOW",
    "REF": "REFERENCE",
    "REFERENCE": "REFERENCE",
    "ARGUMENT": "ARGUMENT",
    "CALL": "CALL",
    "AST": "AST",
    "CONTAINS": "CONTAINS",
    "CFG": "CONTROL_FLOW",
    "DOMINATE": "DOMINANCE",
    "POST_DOMINATE": "POST_DOMINANCE",
    "CONTROL_DEPENDENCY": "CONTROL_DEPENDENCY",
    "CONTROLS": "CONTROL_DEPENDENCY",
}


def canonical_node_type(raw_type: str) -> str:
    value = norm(raw_type).upper()
    if value in CANONICAL_NODE_ALIASES:
        return CANONICAL_NODE_ALIASES[value]

    if value.endswith("_PARAMETER"):
        return "PARAMETER"
    if value in {"FUNCTION", "FUNCTION_DECL", "METHOD_DECLARATION"}:
        return "METHOD"
    if value in {"SOURCE_FILE", "COMPILATION_UNIT"}:
        return "FILE"
    return value


def canonical_edge_types(raw_type: str) -> list[str]:
    value = norm(raw_type).upper()
    mapped = CANONICAL_EDGE_ALIASES.get(value)
    return [mapped] if mapped else [value]


def canonicalize_graph(
    graph: Graph, *, analyzer: str | None = None, analyzer_version: str | None = None
) -> Graph:
    """Return a detached, analyzer-neutral canonical graph.

    Raw parser observations remain available in node/edge properties. Canonical relation
    categories live in metadata and are never substituted for the raw edge type. This lets
    semantic patterns avoid depending on accidental Joern naming.
    """
    g = enrich_graph(deepcopy(graph))
    for n in g.nodes.values():
        d = n.properties.setdefault("derived", {})
        d.setdefault("canonical_node_type", canonical_node_type(n.type))
        d.setdefault("canonical_node_id", n.id)
    for e in g.edges:
        e.properties = dict(e.properties)
        e.properties.setdefault("canonical_edge_types", canonical_edge_types(e.type))
        e.properties.setdefault("canonical_edge_type", canonical_edge_types(e.type)[0])
    manifest_supplied = (
        "analysis_completeness" in g.metadata
        or "completeness_manifest" in g.metadata
    )
    raw_completeness = g.metadata.get("analysis_completeness")
    if not raw_completeness:
        raw_completeness = g.metadata.get("completeness_manifest")
    if isinstance(raw_completeness, dict):
        completeness = dict(raw_completeness)
    elif not manifest_supplied:
        completeness = {
            "graph": "COMPLETE"
            if g.metadata.get("completeness", "declared") in {"full_export", "declared"}
            else "PARTIAL",
            "nodes": "COMPLETE",
            "edges": "COMPLETE",
            "dataflow": "UNKNOWN",
            "control_flow": "UNKNOWN",
            "object_identity": "UNKNOWN",
            "numeric_range": "UNKNOWN",
            "interprocedural": "UNKNOWN",
        }
    else:
        completeness = {}
        g.metadata["analysis_completeness_invalid"] = True
    g.metadata["canonical"] = True
    g.metadata["canonical_version"] = CANONICAL_GRAPH_VERSION
    g.metadata["canonical_schema_version"] = SCHEMA_VERSION
    g.metadata["canonical_source"] = {
        "analyzer": analyzer
        or g.metadata.get("analyzer")
        or g.metadata.get("parser")
        or "unknown",
        "analyzer_version": analyzer_version
        or g.metadata.get("analyzer_version")
        or g.metadata.get("parser_version")
        or "unknown",
    }
    g.metadata["analysis_completeness"] = completeness
    capability = dict(g.metadata.get("capability_manifest") or {})
    capability.setdefault("analyzer", g.metadata["canonical_source"]["analyzer"])
    capability.setdefault(
        "analyzer_version", g.metadata["canonical_source"]["analyzer_version"]
    )
    capability.setdefault(
        "supported_node_types",
        sorted({canonical_node_type(n.type) for n in g.nodes.values()}),
    )
    capability.setdefault(
        "supported_relations",
        sorted({canonical_edge_types(e.type)[0] for e in g.edges}),
    )
    capability.setdefault("analysis_dimensions", sorted(set(completeness)))
    capability.setdefault(
        "completeness_states", sorted({str(v).upper() for v in completeness.values()})
    )
    capability["capability_schema_version"] = "1.0"
    g.metadata["capability_manifest"] = capability
    g.metadata["semantic_layer"] = "EvidenceLab-Canonical-Semantic-1"
    g.metadata["raw_graph_digest"] = graph.digest()
    g.metadata["canonical_graph_digest"] = g.digest()
    return g


def graph_to_dict(graph: Graph) -> dict[str, Any]:
    g = graph if graph.metadata.get("canonical") else canonicalize_graph(graph)
    digest = g.digest()
    return {
        "schema_version": SCHEMA_VERSION,
        "format": CANONICAL_GRAPH_FORMAT,
        "canonical_version": CANONICAL_GRAPH_VERSION,
        "digest": digest,
        "metadata": g.metadata,
        "nodes": [
            {"id": n.id, "type": n.type, "properties": n.properties}
            for n in sorted(g.nodes.values(), key=lambda x: x.id)
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
            }
            for e in sorted(
                g.edges, key=lambda x: (x.source, x.target, x.type, x.id or "")
            )
        ],
    }


def semantic_graph_fingerprint(graph: Graph) -> str:
    """Fingerprint semantic topology, not parser-specific node identifiers.

    A Weisfeiler-Lehman style refinement is used so two graphs with identical node/edge
    counts but different data-flow/control topology are not treated as the same scenario.
    Normalized analysis-completeness states and parser health are also part of the
    fingerprint because incomplete evidence can change a security result to UNKNOWN.
    """
    g = graph if graph.metadata.get("canonical") else canonicalize_graph(graph)
    colors: dict[str, str] = {}
    for n in g.nodes.values():
        d = n.properties.get("derived") or {}
        node_type = canonical_node_type(n.type)
        payload = {
            "type": node_type,
            "external": bool(d.get("potential_external_input")),
            "allocation": bool(d.get("allocation_like")),
            "copy": bool(d.get("copy_like") or d.get("memory_write_like")),
            "capacity_known": bool(d.get("memory_capacity_known")),
            "storage": str(d.get("storage_duration", "UNKNOWN")),
            "region": str(d.get("memory_region", "UNKNOWN")),
            "role": str(d.get("argument_role", "UNKNOWN")),
        }

        if node_type == "LITERAL":
            numeric_value = d.get("numeric_value")
            if not (
                isinstance(numeric_value, (int, float))
                and not isinstance(numeric_value, bool)
            ):
                numeric_value = _num(n.get("code", n.get("CODE")))

            if isinstance(numeric_value, (int, float)) and not isinstance(
                numeric_value, bool
            ):
                payload["literal_numeric_value"] = numeric_value

            string_length = d.get("string_length")
            if isinstance(string_length, int) and not isinstance(string_length, bool):
                payload["literal_string_length"] = string_length

        if node_type == "CALL":
            call_target = (
                d.get("call_name")
                or d.get("name")
                or n.get("name")
                or d.get("method_full_name")
            )
            if call_target:
                payload["call_target"] = norm(str(call_target))

        argument_index = d.get("argument_index")
        if argument_index is not None:
            try:
                payload["argument_index"] = int(argument_index)
            except (TypeError, ValueError, OverflowError):
                payload["argument_index"] = str(argument_index)

        for key in (
            "memory_capacity",
            "memory_capacity_elements",
            "element_count",
            "length",
        ):
            value = d.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                payload[key] = value

        if d.get("capacity_unit") is not None:
            payload["capacity_unit"] = norm(str(d["capacity_unit"])).upper()

        range_value = d.get("range")
        range_lower = (
            _num(range_value.get("lower")) if isinstance(range_value, dict) else None
        )
        range_upper = (
            _num(range_value.get("upper")) if isinstance(range_value, dict) else None
        )

        if range_lower is None or range_upper is None or range_lower > range_upper:
            range_value = n.properties.get("range")
            range_lower = (
                _num(range_value.get("lower"))
                if isinstance(range_value, dict)
                else None
            )
            range_upper = (
                _num(range_value.get("upper"))
                if isinstance(range_value, dict)
                else None
            )

        if (
            isinstance(range_value, dict)
            and range_lower is not None
            and range_upper is not None
            and range_lower <= range_upper
        ):
            range_proof = (
                str(range_value.get("proof", "EXPLICIT_RANGE")).strip().upper()
            )
            payload["numeric_range"] = {
                "lower": range_lower,
                "upper": range_upper,
                "proof": range_proof or "EXPLICIT_RANGE",
            }

        colors[n.id] = hashlib.sha256(stable_json(payload).encode()).hexdigest()
    adjacency: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for e in g.edges:
        rel = e.properties.get("canonical_edge_type") or canonical_edge_types(e.type)[0]
        if e.source in colors and e.target in colors:
            adjacency[e.source].append(("out", str(rel), e.target))
            adjacency[e.target].append(("in", str(rel), e.source))
    for _ in range(3):
        nxt = {}
        for nid, color in colors.items():
            neigh = sorted(
                (direction, rel, colors[other])
                for direction, rel, other in adjacency.get(nid, [])
            )
            payload = {"self": color, "neighbors": neigh}
            nxt[nid] = hashlib.sha256(stable_json(payload).encode()).hexdigest()
        colors = nxt

    edge_sig = Counter(
        (
            str(e.source in colors),
            str(
                e.properties.get("canonical_edge_type")
                or canonical_edge_types(e.type)[0]
            ),
            colors.get(e.source, ""),
            colors.get(e.target, ""),
        )
        for e in g.edges
    )
    node_sig = Counter(colors.values())
    completeness = (
        g.metadata.get("analysis_completeness")
        or g.metadata.get("completeness_manifest")
        or {}
    )
    manifest_supplied = (
        "analysis_completeness" in g.metadata
        or "completeness_manifest" in g.metadata
    )
    if g.metadata.get("analysis_completeness_invalid"):
        completeness = {"manifest": "INVALID"}
    elif not isinstance(completeness, dict):
        completeness = {"manifest": "INVALID"}
    elif not completeness and manifest_supplied:
        completeness = {"manifest": "UNKNOWN"}
    elif not completeness:
        declared = str(g.metadata.get("completeness", "declared")).strip().lower()
        graph_state = (
            "COMPLETE" if declared in {"full_export", "declared"} else "PARTIAL"
        )
        completeness = {
            "graph": graph_state,
            "nodes": "COMPLETE",
            "edges": "COMPLETE",
            "dataflow": "UNKNOWN",
            "control_flow": "UNKNOWN",
            "object_identity": "UNKNOWN",
            "numeric_range": "UNKNOWN",
            "interprocedural": "UNKNOWN",
        }

    completeness_signature = sorted(
        (
            str(key).strip().lower(),
            str(value).strip().upper(),
        )
        for key, value in completeness.items()
    )
    parse_health = str(g.metadata.get("parse_health", "UNKNOWN")).strip().upper()

    payload = {
        "nodes": sorted(node_sig.items()),
        "edges": sorted((stable_json(k), v) for k, v in edge_sig.items()),
        "analysis_completeness": completeness_signature,
        "parse_health": parse_health,
    }
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def semantic_diversity(graphs: list[Graph]) -> dict[str, Any]:
    fps = [semantic_graph_fingerprint(g) for g in graphs]
    unique = len(set(fps))
    n = len(fps)
    duplicate_rate = 0.0 if n == 0 else 1.0 - unique / n
    return {
        "graphs": n,
        "unique_semantic_graphs": unique,
        "semantic_duplicate_rate": round(duplicate_rate, 6),
        "semantic_fingerprint_algorithm": SEMANTIC_FINGERPRINT_ALGORITHM,
        "effective_semantic_independence_ratio": round(unique / n, 6) if n else 0.0,
    }


def canonical_validation(graph: Graph) -> dict[str, Any]:
    errors: list[str] = []
    if not graph.metadata.get("canonical"):
        errors.append("graph is not marked canonical")
    if graph.metadata.get("canonical_version") != CANONICAL_GRAPH_VERSION:
        errors.append("unsupported or missing canonical_version")
    if graph.metadata.get("canonical_schema_version") != SCHEMA_VERSION:
        errors.append("canonical schema version mismatch")
    if not graph.metadata.get("semantic_layer"):
        errors.append("semantic_layer is missing")
    completeness = graph.metadata.get("analysis_completeness")
    if (
        not isinstance(completeness, dict)
        or not completeness
        or graph.metadata.get("analysis_completeness_invalid")
    ):
        errors.append("analysis_completeness manifest is missing or invalid")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "digest": graph.digest(),
    }
