from __future__ import annotations
from . import SCHEMA_VERSION

from pathlib import Path
from typing import Any
import json, os

from .capture import capture_joern
from .provenance import sha256_file


def _placeholder_graph(path: Path, case: dict[str, Any], error: str) -> None:
    """Create an explicit analysis-failure artifact so it evaluates to UNKNOWN."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-canonical-graph",
        "metadata": {
            "completeness": "analysis_failed",
            "parse_health": "DEGRADED",
            "analysis_truncated": True,
            "case_variant": "analysis_failure",
            "failure": error,
            "source_case_id": case.get("id"),
        },
        "nodes": [],
        "edges": [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def capture_dataset(
    dataset_manifest: str | Path,
    out_dir: str | Path,
    benchmark_out: str | Path,
    timeout: int = 600,
    slice_depth: int = 8,
    best_effort: bool = False,
    limit: int | None = None,
    keep_failures_as_unknown: bool = True,
) -> dict[str, Any]:
    """Capture a dataset using Joern and build a benchmark manifest.

    Capture failures are represented as explicit UNKNOWN cases by default, rather than
    being silently dropped. This preserves the denominator and makes analysis coverage
    auditable.
    """
    p = Path(dataset_manifest).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    root = p.parent
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cases = []
    failures = []
    source_cases = [c for c in raw.get("cases", []) if c.get("source")]
    if limit is not None:
        source_cases = source_cases[:limit]
    for idx, c in enumerate(source_cases, 1):
        src = (root / str(c["source"])).resolve()
        cid = str(c["id"])
        case_out = out / cid
        if not src.is_file():
            error = f"source missing: {src}"
            failures.append({"id": cid, "error": error})
            if keep_failures_as_unknown:
                gp = case_out / "canonical-graph.json"
                _placeholder_graph(gp, c, error)
                cases.append(
                    {
                        "id": cid,
                        "expected": str(c.get("expected", "UNKNOWN")).upper(),
                        "actual_policy": "analysis-failure-becomes-UNKNOWN",
                        "graph": os.path.relpath(gp, p.parent),
                        "source": c.get("source"),
                        "partition": c.get("partition", "public"),
                        "tags": list(
                            dict.fromkeys(
                                list(c.get("tags", []))
                                + ["incomplete_analysis", "analysis_completeness"]
                            )
                        ),
                        "dimensions": list(
                            dict.fromkeys(
                                list(c.get("dimensions", []))
                                + ["analysis_completeness"]
                            )
                        ),
                        "dataset": c.get("dataset", {}),
                        "source_metadata": c.get("source_metadata", {}),
                        "capture": {"status": "FAILED", "error": error},
                        "analysis": {"status": "UNKNOWN", "reason": "CAPTURE_FAILED"},
                    }
                )
            continue
        try:
            manifest = capture_joern(
                src,
                case_out,
                dataflow=True,
                dataflow_timeout=timeout,
                dataflow_slice_depth=slice_depth,
                dataflow_file_filter=src.name,
                best_effort_dataflow=best_effort,
            )
            graphml = Path(manifest["artifacts"]["graphml"])
            dataflow = (
                Path(manifest["artifacts"]["dataflow"])
                if manifest["artifacts"].get("dataflow")
                else None
            )
            from .scanner import _merge

            merged = _merge([graphml] + ([dataflow] if dataflow else []))
            attestation = manifest.get("analysis_attestation", {})
            if (
                isinstance(attestation, dict)
                and str(attestation.get("level", "")).upper() == "ANALYZER_ATTESTED"
            ):
                from .capture import validate_capture_manifest_for_merge

                merged.metadata["analysis_attestation"] = (
                    validate_capture_manifest_for_merge(
                        case_out / "capture-manifest.json",
                        [graphml] + ([dataflow] if dataflow else []),
                    )
                )
            else:
                merged.metadata["analysis_attestation"] = attestation
            merged.metadata["capture_manifest"] = str(
                case_out / "capture-manifest.json"
            )
            graph_rel = case_out / "canonical-graph.json"
            payload = {
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
            graph_rel.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            dimensions = list(c.get("dimensions", []))
            tags = list(c.get("tags", []))
            case = dict(c)
            case["graph"] = os.path.relpath(graph_rel, p.parent)
            case["graph_sha256"] = sha256_file(graph_rel)
            case["capture"] = {
                "status": "PASS",
                "manifest": os.path.relpath(
                    case_out / "capture-manifest.json", p.parent
                ),
                "graph_sha256": case["graph_sha256"],
            }
            case["dimensions"] = dimensions
            case["tags"] = tags
            cases.append(case)
        except Exception as exc:
            error = str(exc)
            failures.append({"id": cid, "error": error})
            if keep_failures_as_unknown:
                gp = case_out / "canonical-graph.json"
                _placeholder_graph(gp, c, error)
                cases.append(
                    {
                        "id": cid,
                        "expected": str(c.get("expected", "UNKNOWN")).upper(),
                        "actual_policy": "analysis-failure-becomes-UNKNOWN",
                        "graph": os.path.relpath(gp, p.parent),
                        "source": c.get("source"),
                        "partition": c.get("partition", "public"),
                        "tags": list(
                            dict.fromkeys(
                                list(c.get("tags", []))
                                + ["incomplete_analysis", "analysis_completeness"]
                            )
                        ),
                        "dimensions": list(
                            dict.fromkeys(
                                list(c.get("dimensions", []))
                                + ["analysis_completeness"]
                            )
                        ),
                        "dataset": c.get("dataset", {}),
                        "source_metadata": c.get("source_metadata", {}),
                        "capture": {"status": "FAILED", "error": error},
                        "analysis": {"status": "UNKNOWN", "reason": "CAPTURE_FAILED"},
                    }
                )
    bench = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-benchmark",
        "manifest_id": f"{raw.get('dataset', {}).get('name', p.stem)}-joern-captured-{SCHEMA_VERSION}",
        "source_dataset": raw.get("dataset", {}),
        "cases": cases,
        "capture_policy": {
            "failed_cases_become_unknown": keep_failures_as_unknown,
            "per_case_timeout_seconds": timeout,
        },
    }
    bo = Path(benchmark_out).resolve()
    bo.parent.mkdir(parents=True, exist_ok=True)
    bo.write_text(
        json.dumps(bench, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    status = "PASS" if not failures else ("DEGRADED" if cases else "FAIL")
    return {
        "status": status,
        "requested": len(source_cases),
        "captured": sum(
            1 for c in cases if c.get("capture", {}).get("status") == "PASS"
        ),
        "failed": len(failures),
        "unknown_from_failures": sum(
            1 for c in cases if c.get("capture", {}).get("status") == "FAILED"
        ),
        "failures": failures,
        "benchmark": str(bo),
    }
