from __future__ import annotations
from . import SCHEMA_VERSION

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .capture import capture_joern, validate_capture_manifest_for_merge
from .parsers import parse_graph
from .semantics import enrich_graph
from .spec import Pattern
from .matcher import Matcher
from .witness_replay import WitnessReplay
from .provenance import sha256_file, sha256_json, environment_snapshot


def _merge(graph_paths: list[Path]):
    merged = None
    source_meta = []
    for p in graph_paths:
        g = enrich_graph(parse_graph(p))
        source_meta.append(
            {
                "path": str(p),
                "sha256": sha256_file(p),
                "format": g.metadata.get("format"),
            }
        )
        if merged is None:
            merged = g
            continue
        for nid, n in g.nodes.items():
            if nid not in merged.nodes:
                merged.add_node(n)
            else:
                for k, v in n.properties.items():
                    if merged.nodes[nid].properties.get(k) in (None, "", [], {}):
                        merged.nodes[nid].properties[k] = v
        existing = {(e.id, e.source, e.target, e.type) for e in merged.edges}
        for e in g.edges:
            if (e.id, e.source, e.target, e.type) not in existing:
                merged.add_edge(e)
    if merged is None:
        raise ValueError("no graph artifacts available")
    merged.metadata["merge_sources"] = source_meta
    return merged


def scan_source(
    source: str | Path,
    patterns: Iterable[str | Path],
    out_dir: str | Path,
    *,
    dataflow_timeout: int = 300,
    dataflow_slice_depth: int = 8,
    keep_capture: bool = True,
) -> dict[str, Any]:
    src = Path(source).resolve()
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    temp_capture = out / "capture"
    capture = capture_joern(
        src,
        temp_capture,
        dataflow=True,
        dataflow_timeout=dataflow_timeout,
        dataflow_slice_depth=dataflow_slice_depth,
        dataflow_file_filter=src.name,
        best_effort_dataflow=True,
    )
    graphml = Path(capture["artifacts"]["graphml"])
    dataflow = (
        Path(capture["artifacts"]["dataflow"])
        if capture["artifacts"].get("dataflow")
        else None
    )
    merge_inputs = [graphml] + ([dataflow] if dataflow else [])
    merged = _merge(merge_inputs)

    if str(capture.get("status", "")).upper() == "PASS":
        attestation = validate_capture_manifest_for_merge(
            temp_capture / "capture-manifest.json",
            merge_inputs,
        )
    else:
        attestation = capture.get("analysis_attestation", {})

    merged.metadata["analysis_attestation"] = attestation
    merged.metadata["capture_manifest"] = str(temp_capture / "capture-manifest.json")
    merged_path = out / "canonical-graph.json"
    merged_payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-canonical-graph",
        "digest": merged.digest(),
        "metadata": merged.metadata,
        "nodes": [
            {"id": n.id, "type": n.type, "properties": n.properties}
            for n in merged.nodes.values()
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
            }
            for e in merged.edges
        ],
    }
    merged_path.write_text(
        json.dumps(merged_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    results = []
    for pat_path in patterns:
        pp = Path(pat_path).resolve()
        pat = Pattern.load(pp)
        match = Matcher(merged).run(pat).to_dict()
        validation = WitnessReplay(merged, pat).validate(match)
        result = {
            "pattern": str(pp),
            "pattern_id": pat.pattern_id,
            "cwe": pat.cwe,
            "match": match,
            "witness_replay": validation,
        }
        result_path = out / (pat.pattern_id + ".json")
        result_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        results.append(
            {
                "pattern_id": pat.pattern_id,
                "cwe": pat.cwe,
                "status": match["status"],
                "witness_replay": validation["status"],
                "report": str(result_path),
            }
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-scan-result",
        "source": str(src),
        "source_sha256": sha256_file(src),
        "environment": environment_snapshot(src.parent),
        "capture": capture,
        "canonical_graph": str(merged_path),
        "graph_digest": merged.digest(),
        "results": results,
        "digest": None,
    }
    payload["digest"] = sha256_json({k: v for k, v in payload.items() if k != "digest"})
    report = out / "scan.json"
    report.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if not keep_capture:
        import shutil

        shutil.rmtree(temp_capture, ignore_errors=True)
    return {
        "status": "PASS"
        if all(r["witness_replay"] == "PASS" for r in results)
        else "FAIL",
        "report": str(report),
        "graph": str(merged_path),
        "results": results,
        "graph_digest": merged.digest(),
    }
