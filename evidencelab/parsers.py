from __future__ import annotations

from .attestation import is_trusted_attestation
import gzip, json, re, xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from .errors import InputFormatError
from .models import Edge, Graph, Node, norm, key_norm

TYPE_KEYS = (
    "type",
    "nodeType",
    "node_type",
    "label",
    "_label",
    "kind",
    "nodeLabel",
    "NODE_TYPE",
    "labelV",
)
EDGE_TYPE_KEYS = (
    "type",
    "edgeType",
    "edge_type",
    "label",
    "_label",
    "kind",
    "relationship",
    "relation",
    "labelE",
)


@dataclass(frozen=True, slots=True)
class GraphMLKey:
    id: str
    scope: str
    attr_name: str
    attr_type: str | None
    default: Any = None


def _read_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    return gzip.decompress(raw) if path.suffix.lower() == ".gz" else raw


def _coerce(value: Any, declared: str | None = None) -> Any:
    if not isinstance(value, str):
        if isinstance(value, list):
            return [_coerce(x) for x in value]
        if isinstance(value, dict):
            return {str(k): _coerce(v) for k, v in value.items()}
        return value
    s = value.strip()
    d = (declared or "").lower()
    if d in {"string", "uri", "date", "dateTime".lower()}:
        return value
    if d in {"boolean", "bool"}:
        return s.lower() == "true" if s.lower() in {"true", "false"} else value
    if d in {"int", "integer", "long", "short", "byte"}:
        try:
            return int(s)
        except ValueError:
            return value
    if d in {"float", "double", "decimal"}:
        try:
            return float(s)
        except ValueError:
            return value
    if s.lower() in {"true", "false"}:
        return s.lower() == "true"
    if re.fullmatch(r"[-+]?\d+", s):
        try:
            return int(s)
        except ValueError:
            pass
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][-+]?\d+)?", s):
        try:
            return float(s)
        except ValueError:
            pass
    return value


def _first(props: dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for k in keys:
        if k in props and props[k] not in (None, ""):
            return props[k]
    wanted = {key_norm(k) for k in keys}
    for k, v in props.items():
        if key_norm(k) in wanted and v not in (None, ""):
            return v
    return default


def _schema_label_from_key(key_id: str, scope: str) -> str | None:
    parts = key_id.split("__")
    if len(parts) >= 3 and parts[0].lower() == scope and parts[1]:
        return parts[1]
    return None


def _schema_prop_from_key(key_id: str, scope: str) -> str | None:
    parts = key_id.split("__")
    if len(parts) >= 3 and parts[0].lower() == scope:
        return "__".join(parts[2:])
    return None


def _looks_like_label(v: Any) -> bool:
    return isinstance(v, str) and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", v.strip()))


def _key_defs(root: ET.Element) -> dict[tuple[str, str], GraphMLKey]:
    out: dict[tuple[str, str], GraphMLKey] = {}
    for key in root.findall("./{*}key"):
        kid = key.attrib.get("id")
        if not kid:
            continue
        scope = key.attrib.get("for", "all").lower()
        attr_name = key.attrib.get("attr.name") or key.attrib.get("name") or kid
        attr_type = key.attrib.get("attr.type")
        d = key.find("{*}default")
        default = _coerce(d.text or "", attr_type) if d is not None else None
        out[(scope, kid)] = GraphMLKey(kid, scope, attr_name, attr_type, default)
    return out


def _key_lookup(
    defs: dict[tuple[str, str], GraphMLKey], kid: str, scope: str
) -> GraphMLKey | None:
    return (
        defs.get((scope, kid))
        or defs.get(("all", kid))
        or next(
            (v for (s, k), v in defs.items() if k == kid and s in {scope, "all"}), None
        )
    )


def _parse_data(
    el: ET.Element, defs: dict[tuple[str, str], GraphMLKey], scope: str
) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for data in el.findall("./{*}data"):
        kid = data.attrib.get("key", "")
        kd = _key_lookup(defs, kid, scope)
        fallback_label = _schema_label_from_key(kid, scope)
        fallback_prop = _schema_prop_from_key(kid, scope)
        name = kd.attr_name if kd else (fallback_prop or kid or "data")
        value = _coerce(data.text or "", kd.attr_type if kd else None)
        props[name] = value
        if fallback_label:
            props.setdefault("_schema_label", fallback_label)
    return props


def _canonical_node_type(props: dict[str, Any]) -> str:
    v = _first(props, TYPE_KEYS)
    if v not in (None, ""):
        return norm(v)
    return norm(props.get("_schema_label")) if props.get("_schema_label") else "UNKNOWN"


def _canonical_edge_type(props: dict[str, Any]) -> str:
    v = _first(props, EDGE_TYPE_KEYS)
    if v not in (None, ""):
        return norm(v)
    return norm(props.get("_schema_label")) if props.get("_schema_label") else "UNKNOWN"


def parse_graphml(path: Path) -> Graph:
    raw = _read_bytes(path)
    head = raw[:8192].decode("utf-8", errors="ignore").upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise InputFormatError("GraphML with DTD/entity declarations is rejected")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, OSError) as exc:
        raise InputFormatError(f"Cannot parse GraphML: {exc}") from exc
    if root.tag.split("}")[-1].lower() != "graphml":
        raise InputFormatError("Not GraphML")
    defs = _key_defs(root)
    g = Graph(
        metadata={
            "format": "graphml",
            "source": str(path),
            "parser": "joern-flatgraph-graphml",
            "parser_version": "1.0",
            "completeness": "full_export",
        }
    )
    g.metadata["graphml_keys"] = [vars_to_dict(k) for k in defs.values()]
    graph_el = root.find("./{*}graph")
    if graph_el is None:
        graph_el = root.find(".//{*}graph")
    if graph_el is None:
        g.metadata["parser_issues"] = [
            {"code": "GML001", "severity": "ERROR", "message": "No graph element"}
        ]
        finalize(g)
        return g
    node_els = graph_el.findall("./{*}node")
    edge_els = graph_el.findall("./{*}edge")
    if any(
        k.id.startswith("node__") or k.id.startswith("edge__") for k in defs.values()
    ):
        g.metadata["joern_style"] = True
    # GraphML exporter used by Joern/Flatgraph is intentionally lossy for list-valued properties.
    g.metadata["loss_risk"] = {
        "graphml_lists": True,
        "reason": "GraphML export may discard list-valued properties",
    }
    for el in node_els:
        nid = el.attrib.get("id")
        if nid is None:
            continue
        props = _parse_data(el, defs, "node")
        props.update({k: _coerce(v) for k, v in el.attrib.items() if k != "id"})
        if str(nid) in g.nodes:
            g.metadata.setdefault("parser_issues", []).append(
                {
                    "code": "GML003",
                    "severity": "ERROR",
                    "message": f"Duplicate node id {nid}",
                }
            )
        g.add_node(Node(str(nid), _canonical_node_type(props), props))
    for el in edge_els:
        src, dst = el.attrib.get("source"), el.attrib.get("target")
        if src is None or dst is None:
            continue
        props = _parse_data(el, defs, "edge")
        props.update(
            {
                k: _coerce(v)
                for k, v in el.attrib.items()
                if k not in {"source", "target"}
            }
        )
        g.add_edge(
            Edge(
                str(src),
                str(dst),
                _canonical_edge_type(props),
                props,
                el.attrib.get("id"),
            )
        )
    finalize(g)
    return g


def _unwrap(v: Any) -> Any:
    if isinstance(v, dict):
        t = str(v.get("@type", "")).lower()
        if "@value" in v:
            x = _unwrap(v["@value"])
            if isinstance(x, str):
                if "int" in t or "long" in t:
                    try:
                        return int(x)
                    except ValueError:
                        pass
                if "float" in t or "double" in t or "decimal" in t:
                    try:
                        return float(x)
                    except ValueError:
                        pass
                if "boolean" in t or t.endswith(":bool"):
                    if x.lower() in {"true", "false"}:
                        return x.lower() == "true"
            return x
        if "value" in v and set(v).issubset({"value", "id", "@type", "type"}):
            return _unwrap(v["value"])
        return {str(k): _unwrap(x) for k, x in v.items() if k != "@type"}
    if isinstance(v, list):
        return [_unwrap(x) for x in v]
    return v


def _prop_unwrap(v: Any) -> Any:
    if isinstance(v, list):
        return [_prop_unwrap(x) for x in v]
    if isinstance(v, dict):
        if "@value" in v:
            return _prop_unwrap(v["@value"])
        if "value" in v and not any(k in v for k in ("name", "code", "label")):
            return _prop_unwrap(v["value"])
        return {
            str(k): _prop_unwrap(x) for k, x in v.items() if k not in {"@type", "id"}
        }
    return v


def parse_graphson(path: Path) -> Graph:
    try:
        raw = json.loads(_read_bytes(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputFormatError(f"Cannot parse GraphSON: {exc}") from exc
    # Unwrap only the GraphSON envelope; preserve typed property values until _prop_unwrap.
    if (
        isinstance(raw, dict)
        and "@value" in raw
        and str(raw.get("@type", "")).lower() in {"tinker:graph", "graph"}
    ):
        raw = raw["@value"]
    elif isinstance(raw, dict) and "graph" in raw and isinstance(raw["graph"], dict):
        raw = raw["graph"]
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("vertices"), list)
        or not isinstance(raw.get("edges"), list)
    ):
        raise InputFormatError("Unsupported GraphSON: expected vertices/edges")
    g = Graph(
        metadata={
            "format": "graphson",
            "source": str(path),
            "parser": "joern-flatgraph-graphson",
            "parser_version": "1.0",
            "completeness": "full_export",
        }
    )
    for v in raw["vertices"]:
        if not isinstance(v, dict) or v.get("id") is None:
            continue
        props = _prop_unwrap(v.get("properties") or {})
        if not isinstance(props, dict):
            props = {}
        if v.get("label") is not None:
            props.setdefault("label", _unwrap(v.get("label")))
        ntype = norm(_first({"label": v.get("label"), **props}, ("label",)))
        raw_attrs = {
            k: _unwrap(val) for k, val in v.items() if k not in {"id", "properties"}
        }
        props.update(raw_attrs)
        g.add_node(Node(str(_unwrap(v["id"])), ntype, props))
    for e in raw["edges"]:
        if not isinstance(e, dict):
            continue
        src, dst = (
            _unwrap(e.get("outV", e.get("source"))),
            _unwrap(e.get("inV", e.get("target"))),
        )
        if src is None or dst is None:
            continue
        props = _prop_unwrap(e.get("properties") or {})
        if not isinstance(props, dict):
            props = {}
        label = _unwrap(e.get("label", e.get("type", "UNKNOWN")))
        props.setdefault("label", label)
        g.add_edge(
            Edge(
                str(src),
                str(dst),
                norm(label),
                props,
                str(_unwrap(e["id"])) if e.get("id") is not None else None,
            )
        )
    finalize(g)
    return g


def parse_dataflow_slice(path: Path) -> Graph:
    try:
        raw = json.loads(_read_bytes(path).decode("utf-8"))
    except Exception as exc:
        raise InputFormatError(f"Cannot parse Joern DataFlowSlice: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("$type") != "DataFlowSlice":
        raise InputFormatError("Not a Joern DataFlowSlice")
    g = Graph(
        metadata={
            "format": "joern-dataflow-slice",
            "source": str(path),
            "parser": "joern-slice",
            "parser_version": "1.0",
            "completeness": "partial_slice",
        }
    )
    for n in raw.get("nodes", []):
        if isinstance(n, dict) and n.get("id") is not None:
            props = {k: v for k, v in n.items() if k not in {"id", "label"}}
            g.add_node(Node(str(n["id"]), norm(n.get("label")), props))
    for e in raw.get("edges", []):
        if (
            isinstance(e, dict)
            and e.get("src") is not None
            and e.get("dst") is not None
        ):
            g.add_edge(
                Edge(str(e["src"]), str(e["dst"]), norm(e.get("label")), {}, None)
            )
    finalize(g)
    return g


def parse_flow_paths(path: Path) -> Graph:
    try:
        raw = json.loads(_read_bytes(path).decode("utf-8"))
    except Exception as exc:
        raise InputFormatError(f"Cannot parse Joern flow paths: {exc}") from exc
    if not isinstance(raw, list):
        raise InputFormatError("Flow path JSON must be a list")
    g = Graph(
        metadata={
            "format": "joern-flow-paths",
            "source": str(path),
            "parser": "reachableByFlows",
            "parser_version": "1.0",
            "completeness": "partial_flow",
        }
    )
    for flow in raw:
        elems = flow.get("elements", []) if isinstance(flow, dict) else []
        prev = None
        for x in elems:
            if not isinstance(x, dict) or x.get("_id") is None:
                continue
            nid = str(x["_id"])
            props = {k: v for k, v in x.items() if k not in {"_id", "_label"}}
            g.add_node(Node(nid, norm(x.get("_label")), props))
            if prev is not None:
                g.add_edge(Edge(prev, nid, "DATA_FLOW", {}, None))
            prev = nid
    finalize(g)
    return g


def parse_generic_json(path: Path) -> Graph:
    try:
        raw = json.loads(_read_bytes(path).decode("utf-8"))
    except Exception as exc:
        raise InputFormatError(f"Cannot parse JSON graph: {exc}") from exc
    if isinstance(raw, dict) and isinstance(raw.get("nodes"), list):
        declared = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        g = Graph(
            metadata={
                "format": "json",
                "source": str(path),
                "parser": "canonical-json",
                "parser_version": "1.1",
                "completeness": "declared",
            }
        )
        # Preserve proof-relevant operational metadata without treating arbitrary fields as parser metadata.
        g.metadata["declared_metadata"] = dict(declared)
        for key in (
            "completeness",
            "parse_health",
            "candidate_truncated",
            "loss_risk",
            "case_variant",
            "analysis_truncated",
        ):
            if key in declared:
                g.metadata[key] = declared[key]
        declared_attestation = declared.get("analysis_attestation")
        capture_manifest = declared.get("capture_manifest")
        merge_sources = declared.get("merge_sources")
        source_paths: list[Path] = []

        if (
            raw.get("format") == "evidencelab-canonical-graph"
            and isinstance(declared_attestation, dict)
            and str(declared_attestation.get("level", "")).upper()
            == "ANALYZER_ATTESTED"
            and isinstance(capture_manifest, str)
            and capture_manifest.strip()
            and isinstance(merge_sources, list)
            and merge_sources
        ):
            try:
                manifest_file = Path(capture_manifest).expanduser()
                if not manifest_file.is_absolute():
                    manifest_file = path.parent / manifest_file
                manifest_file = manifest_file.resolve()

                source_paths = []
                source_hashes = []
                normalized_sources = []

                for record in merge_sources:
                    if not isinstance(record, dict):
                        raise ValueError("invalid merge-source record")

                    raw_path = record.get("path")
                    if not isinstance(raw_path, str) or not raw_path.strip():
                        raise ValueError("merge-source record has no path")

                    source_path = Path(raw_path).expanduser()
                    if not source_path.is_absolute():
                        source_path = path.parent / source_path
                    source_path = source_path.resolve()

                    source_paths.append(source_path)
                    source_hashes.append(record.get("sha256"))
                    normalized_sources.append(
                        {**record, "path": str(source_path)}
                    )

                from .capture import validate_capture_manifest_for_merge

                verified = validate_capture_manifest_for_merge(
                    manifest_file,
                    source_paths,
                )

                verified_hashes = verified["verified_merge_input_sha256"]
                expected_hashes = [verified_hashes["graphml"]]
                if "dataflow" in verified_hashes:
                    expected_hashes.append(verified_hashes["dataflow"])

                if (
                    source_hashes == expected_hashes
                    and is_trusted_attestation(verified)
                ):
                    # Use the validator's result, not serialized attestation fields.
                    g.metadata["analysis_attestation"] = verified
                    g.metadata["capture_manifest"] = str(manifest_file)
                    g.metadata["merge_sources"] = normalized_sources

            except Exception:
                # Invalid or unavailable capture evidence must not be promoted.
                pass
        # Preserve any explicitly authored integrity/provenance records as data.
        if "merge_sources" in declared:
            g.metadata["merge_sources"] = declared["merge_sources"]
        if "merge_conflicts" in declared:
            g.metadata["merge_conflicts"] = declared["merge_conflicts"]
        for n in raw["nodes"]:
            if not isinstance(n, dict) or n.get("id") is None:
                continue
            props = dict(n.get("properties") or {})
            props.update(
                {k: v for k, v in n.items() if k not in {"id", "type", "properties"}}
            )
            g.add_node(
                Node(str(n["id"]), norm(n.get("type", props.get("label"))), props)
            )
        for e in raw.get("edges", []):
            if (
                isinstance(e, dict)
                and e.get("source") is not None
                and e.get("target") is not None
            ):
                g.add_edge(
                    Edge(
                        str(e["source"]),
                        str(e["target"]),
                        norm(e.get("type", e.get("label"))),
                        dict(e.get("properties") or {}),
                        str(e.get("id")) if e.get("id") is not None else None,
                    )
                )
        finalize(g)

        claims_analyzer_attestation = (
            isinstance(declared_attestation, dict)
            and str(declared_attestation.get("level", "")).upper()
            == "ANALYZER_ATTESTED"
        )

        if (
            raw.get("format") == "evidencelab-canonical-graph"
            and claims_analyzer_attestation
        ):
            try:
                promoted = g.metadata.get("analysis_attestation")

                if not is_trusted_attestation(promoted):
                    raise ValueError(
                        "capture manifest and merge-input validation failed"
                    )

                declared_digest = raw.get("digest")
                if (
                    not isinstance(declared_digest, str)
                    or declared_digest != g.digest()
                ):
                    raise ValueError("canonical graph digest mismatch")

                if not source_paths:
                    raise ValueError("no verified merge inputs are available")

                # Rebuild using the same merge implementation as the producers.
                # This also catches edits where someone recalculates the JSON digest.
                from .scanner import _merge

                rebuilt = _merge(source_paths)
                if rebuilt.digest() != g.digest():
                    raise ValueError(
                        "canonical graph does not match verified merge inputs"
                    )

            except Exception as exc:
                # Fail closed: preserve the declared metadata for diagnostics,
                # but do not allow the graph to claim a trusted attestation.
                g.metadata.pop("analysis_attestation", None)
                g.metadata.pop("capture_manifest", None)
                g.metadata["parse_health"] = "DEGRADED"
                g.metadata["attestation_integrity_error"] = str(exc)

        return g
    raise InputFormatError("Unsupported JSON graph shape")


def vars_to_dict(obj: Any) -> dict[str, Any]:
    return {
        "id": obj.id,
        "for": obj.scope,
        "attr_name": obj.attr_name,
        "attr_type": obj.attr_type,
    }


def _resolve(path: Path) -> Path:
    if path.is_file():
        return path
    if path.is_dir():
        preferred = ["export.xml", "export.graphml", "export.graphson", "export.json"]
        for name in preferred:
            p = path / name
            if p.is_file():
                return p
        candidates = sorted([p for p in path.glob("export.*") if p.is_file()])
        if candidates:
            return candidates[0]
    raise InputFormatError(f"Graph input not found or unsupported: {path}")


def detect_format(path: str | Path) -> str:
    p = _resolve(Path(path))
    suf = p.suffix.lower()
    if suf in {".xml", ".graphml", ".xml.gz", ".graphml.gz"}:
        return "graphml"
    if suf == ".graphson":
        return "graphson"
    if suf in {".json", ".jsonl", ".json.gz"}:
        try:
            raw = json.loads(_read_bytes(p).decode("utf-8"))
        except Exception:
            return "json"
        if (
            isinstance(raw, list)
            and raw
            and all(isinstance(x, dict) and "elements" in x for x in raw)
        ):
            return "joern-flow-paths"
        if isinstance(raw, dict) and raw.get("$type") == "DataFlowSlice":
            return "joern-dataflow-slice"
        un = _unwrap(raw)
        if isinstance(un, dict) and "vertices" in un and "edges" in un:
            return "graphson"
        return "json"
    raise InputFormatError(f"Unsupported graph format: {suf}")


def finalize(g: Graph) -> None:
    unknown_n = sum(1 for n in g.nodes.values() if n.type == "UNKNOWN")
    unknown_e = sum(1 for e in g.edges if e.type == "UNKNOWN")
    missing = sum(
        1 for e in g.edges if e.source not in g.nodes or e.target not in g.nodes
    )
    g.metadata["integrity"] = {
        "missing_edge_endpoints": missing,
        "unknown_node_types": unknown_n,
        "unknown_edge_types": unknown_e,
    }
    issues = g.metadata.get("parser_issues", [])
    g.metadata["unknown_node_types"] = unknown_n
    g.metadata["unknown_edge_types"] = unknown_e
    computed_health = (
        "INVALID"
        if not g.nodes and not g.edges
        else ("DEGRADED" if unknown_n or unknown_e or missing or issues else "OK")
    )

    # Preserve declared health conservatively: successfully parsing a graph must
    # not erase an upstream DEGRADED/INVALID assessment. Structural problems
    # found here must likewise not be hidden by a declared OK value.
    declared_metadata = g.metadata.get("declared_metadata")
    if (
        isinstance(declared_metadata, dict)
        and "parse_health" in declared_metadata
    ):
        declared_health = declared_metadata.get("parse_health")
    else:
        declared_health = g.metadata.get("parse_health")

    health_rank = {
        "OK": 0,
        "UNKNOWN": 1,
        "DEGRADED": 2,
        "INVALID": 3,
    }

    declared_health = (
        str(declared_health).strip().upper()
        if declared_health is not None
        and str(declared_health).strip()
        else None
    )

    # An unrecognized non-empty health value is not safe to promote to OK.
    if declared_health is not None and declared_health not in health_rank:
        declared_health = "DEGRADED"

    candidates = [computed_health]
    if declared_health is not None:
        candidates.append(declared_health)

    g.metadata["parse_health"] = max(
        candidates, key=lambda health: health_rank[health]
    )


def parse_graph(path: str | Path) -> Graph:
    p = _resolve(Path(path))
    fmt = detect_format(p)
    if fmt == "graphml":
        return parse_graphml(p)
    if fmt == "graphson":
        return parse_graphson(p)
    if fmt == "joern-dataflow-slice":
        return parse_dataflow_slice(p)
    if fmt == "joern-flow-paths":
        return parse_flow_paths(p)
    return parse_generic_json(p)
