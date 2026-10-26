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
    dataset = raw.get("dataset", {}) or {}
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
                        "label": c.get("label"),
                        "expected": str(c.get("expected", "UNKNOWN")).upper(),
                        "actual_policy": "analysis-failure-becomes-UNKNOWN",
                        "graph": os.path.relpath(gp, p.parent),
                        "source": c.get("source"),
                        "label": c.get("label"),
                        "label_authority": c.get("label_authority")
                        or dataset.get("label_authority")
                        or "USER_DECLARED",
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
                        "label": c.get("label"),
                        "expected": str(c.get("expected", "UNKNOWN")).upper(),
                        "actual_policy": "analysis-failure-becomes-UNKNOWN",
                        "graph": os.path.relpath(gp, p.parent),
                        "source": c.get("source"),
                        "label": c.get("label"),
                        "label_authority": c.get("label_authority")
                        or dataset.get("label_authority")
                        or "USER_DECLARED",
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


def capture_source_dataset(
    dataset_manifest: str | Path,
    out_dir: str | Path,
    timeout: int = 600,
    slice_depth: int = 8,
    best_effort: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    p = Path(dataset_manifest).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("manifest root must be an object")
    dataset = raw.get("dataset") or {}
    if not isinstance(dataset, dict):
        raise ValueError("manifest dataset must be an object")
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases array")
    seen_ids = set()
    source_root = p.parent.resolve()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"case at index {index} must be an object")
        case_id = str(case.get("id", "")).strip()
        if not case_id or case_id in {".", ".."} or "/" in case_id or "\\" in case_id:
            raise ValueError(f"case at index {index} has an invalid id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        label = str(case.get("label", "")).strip().lower()
        if label not in {"safe", "vulnerable"}:
            raise ValueError(f"case {case_id} label must be safe or vulnerable")
        source = str(case.get("source", "")).strip()
        if not source:
            raise ValueError(f"case {case_id} requires a source path")
        source_path = Path(source)
        if source_path.is_absolute():
            raise ValueError(f"case {case_id} source path must be relative")
        resolved_source = (source_root / source_path).resolve()
        try:
            resolved_source.relative_to(source_root)
        except ValueError as exc:
            raise ValueError(f"case {case_id} source path escapes manifest directory") from exc
        if resolved_source.suffix.lower() not in {
            ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"
        }:
            raise ValueError(f"case {case_id} source must be a C or C++ file")
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    benchmark_path = out / "benchmark.json"
    capture_result = capture_dataset(
        p,
        out / "captures",
        benchmark_path,
        timeout,
        slice_depth,
        best_effort,
        limit,
        True,
    )
    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    output_paths = {
        "safe": out / "safe.json",
        "vulnerable": out / "vulnerable.json",
    }
    written = {}
    for label, output_path in output_paths.items():
        selected = []
        for original in benchmark.get("cases", []):
            if str(original.get("label", "")).lower() != label:
                continue
            item = dict(original)
            graph_ref = item.get("graph")
            if graph_ref:
                graph_path = (p.parent / str(graph_ref)).resolve()
                item["graph"] = os.path.relpath(graph_path, output_path.parent)
                if graph_path.is_file():
                    item["graph_sha256"] = sha256_file(graph_path)
            capture = item.get("capture")
            if isinstance(capture, dict) and capture.get("manifest"):
                capture = dict(capture)
                manifest_path = (p.parent / str(capture["manifest"])).resolve()
                capture["manifest"] = os.path.relpath(manifest_path, output_path.parent)
                item["capture"] = capture
            source_value = item.get("source")
            if source_value:
                source_path = (source_root / str(source_value)).resolve()
                if source_path.is_file():
                    item["source_sha256"] = sha256_file(source_path)
            item["label"] = label
            item["label_authority"] = str(
                item.get("label_authority")
                or dataset.get("label_authority")
                or "USER_DECLARED"
            )
            selected.append(item)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "format": "evidencelab-source-dataset",
            "dataset": dict(dataset),
            "label": label,
            "label_authority": str(
                dataset.get("label_authority") or "USER_DECLARED"
            ),
            "source_root": str(source_root),
            "source_manifest": str(p),
            "cases": selected,
            "capture_policy": {
                "failed_analysis_is_unknown": True,
                "per_case_timeout_seconds": timeout,
            },
        }
        output_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        written[label] = {"path": str(output_path), "cases": len(selected)}
    return {
        "status": capture_result["status"],
        "requested": capture_result["requested"],
        "captured": capture_result["captured"],
        "failed": capture_result["failed"],
        "unknown_from_failures": capture_result["unknown_from_failures"],
        "datasets": written,
        "benchmark": str(benchmark_path),
        "failures": capture_result["failures"],
    }
