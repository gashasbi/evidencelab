from __future__ import annotations
from pathlib import Path
from typing import Any
import json, hashlib
from .models import Graph, Node, Edge
from .provenance import sha256_json


def _uri(loc: dict[str, Any]) -> tuple[str | None, int | None, int | None]:
    pl = loc.get("physicalLocation", {}) or {}
    art = pl.get("artifactLocation", {}) or {}
    reg = pl.get("region", {}) or {}
    return art.get("uri"), reg.get("startLine"), reg.get("startColumn")


def sarif_to_graph(path: str | Path) -> Graph:
    p = Path(path).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    g = Graph(
        metadata={
            "format": "sarif-observation-graph",
            "source": str(p),
            "parser": "evidencelab-sarif-ingest",
            "parser_version": "1.0",
            "completeness": "declared",
        }
    )
    for ri, run in enumerate(raw.get("runs", [])):
        for rj, result in enumerate(run.get("results", []) or []):
            rid = str(result.get("ruleId") or "rule")
            rr = f"run{ri}:result{rj}"
            g.add_node(
                Node(
                    rr,
                    "SARIF_RESULT",
                    {
                        "ruleId": rid,
                        "level": result.get("level"),
                        "message": (result.get("message") or {}).get("text"),
                        "provenance": {"source": str(p), "result_index": rj},
                    },
                )
            )
            prev = rr
            locs = list(result.get("locations", []) or [])
            for i, loc in enumerate(locs):
                uri, line, col = _uri(loc)
                nid = f"{rr}:loc{i}"
                g.add_node(
                    Node(
                        nid,
                        "LOCATION",
                        {"uri": uri, "line": line, "column": col, "result": rr},
                    )
                )
                g.add_edge(Edge(prev, nid, "LOCATION", {"index": i}))
                prev = nid
            for fi, flow in enumerate(result.get("codeFlows", []) or []):
                for ti, thread in enumerate(flow.get("threadFlows", []) or []):
                    prev_flow = rr
                    base = f"{rr}:flow{fi}:thread{ti}"
                    for li, tloc in enumerate(thread.get("locations", []) or []):
                        uri, line, col = _uri(tloc.get("location", {}) or {})
                        nid = f"{base}:loc{li}"
                        g.add_node(
                            Node(
                                nid,
                                "FLOW_LOCATION",
                                {
                                    "uri": uri,
                                    "line": line,
                                    "column": col,
                                    "thread_flow": base,
                                    "execution_order": tloc.get("executionOrder"),
                                },
                            )
                        )
                        g.add_edge(
                            Edge(
                                prev_flow,
                                nid,
                                "FLOW_STEP",
                                {"execution_order": tloc.get("executionOrder")},
                            )
                        )
                        prev_flow = nid
    g.metadata["input_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
    g.metadata["semantic_provenance"] = sha256_json(g.metadata)
    return g
