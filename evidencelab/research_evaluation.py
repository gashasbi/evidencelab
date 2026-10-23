from __future__ import annotations

"""End-to-end research evaluation orchestration for EvidenceLab."""

from pathlib import Path
from typing import Any
import json
import os
import time

from . import SCHEMA_VERSION, __version__
from .benchmark_quality import quality_audit
from .contract import build_coverage_matrix, artifact_identity, utc_now
from .evaluator import run_manifest
from .performance import profile_pattern
from .profile import load_profile, validate_benchmark_gate, validate_profile
from .research_check import run_research_check
from .spec import Pattern
from .witness_validator import replay_stored_report
from .provenance import sha256_file, sha256_json, environment_snapshot


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def evaluate_benchmark(
    benchmark: str | Path,
    pattern: str | Path,
    out_dir: str | Path,
    *,
    partition: str | None = None,
    replay: bool = True,
    performance_repeats: int = 1,
    max_case_seconds: float | None = None,
    max_case_memory_bytes: int | None = None,
) -> dict[str, Any]:
    bp = Path(benchmark).resolve()
    pp = Path(pattern).resolve()
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pat = Pattern.load(pp)
    raw_benchmark = json.loads(bp.read_text(encoding="utf-8"))
    case_map = {
        str(c.get("id")): c
        for c in raw_benchmark.get("cases", [])
        if isinstance(c, dict)
    }
    results, metrics, meta = run_manifest(
        bp, pat, reveal=True, partition=partition, case_timeout_seconds=max_case_seconds
    )
    cases_dir = out / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    case_reports = []
    for result in results:
        report = {
            "schema_version": SCHEMA_VERSION,
            "format": "evidencelab-evaluation-case",
            "created_at_utc": utc_now(),
            "tool": {"name": "EvidenceLab", "version": __version__},
            "case_id": result.case_id,
            "expected": result.expected,
            "actual": result.actual,
            "correct": result.correct,
            "partition": result.partition,
            "tags": result.tags,
            "graph": str(
                (
                    bp.parent / str((case_map.get(result.case_id) or {}).get("graph"))
                ).resolve()
            )
            if (case_map.get(result.case_id) or {}).get("graph")
            else "",
            "graph_rel": str((case_map.get(result.case_id) or {}).get("graph") or ""),
            "graph_digest": result.graph_digest,
            "pattern": str(pp),
            "pattern_sha256": sha256_file(pp),
            "benchmark": str(bp),
            "matcher": result.detail,
            "replay": None,
        }
        path = cases_dir / f"{result.case_id}.json"
        _write_json(path, report)
        case_reports.append(str(path.relative_to(out)))
    replay_report = None
    if replay:
        replay_report = replay_stored_directory(out, pp)
    perf = profile_pattern(
        bp,
        pat,
        repeats=max(1, performance_repeats),
        partition=partition,
        max_case_seconds=max_case_seconds,
        max_case_memory_bytes=max_case_memory_bytes,
        isolate_cases=(
            max_case_seconds is not None or max_case_memory_bytes is not None
        ),
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-evaluation",
        "created_at_utc": utc_now(),
        "tool": {"name": "EvidenceLab", "version": __version__},
        "benchmark": artifact_identity(bp, kind="benchmark"),
        "pattern": artifact_identity(pp, kind="pattern"),
        "partition": partition,
        "metrics": metrics.to_dict(),
        "benchmark_meta": meta,
        "coverage_matrix": build_coverage_matrix(
            [
                {
                    "expected": x.expected,
                    "tags": x.tags,
                    "dimensions": (case_map.get(x.case_id) or {}).get("dimensions", []),
                }
                for x in results
            ]
        ),
        "performance": perf,
        "stored_case_reports": case_reports,
        "independent_replay": replay_report,
        "environment": environment_snapshot(out),
    }
    summary["evaluation_sha256"] = sha256_json(summary)
    _write_json(out / "summary.json", summary)
    return summary


def replay_stored_directory(
    results_dir: str | Path, pattern: str | Path
) -> dict[str, Any]:
    root = Path(results_dir).resolve()
    pat = Pattern.load(pattern)
    reports = sorted((root / "cases").glob("*.json"))
    errors: list[dict[str, Any]] = []
    passed = 0
    for report_path in reports:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
        graph_ref = str(raw.get("graph", ""))
        if not graph_ref:
            graph_ref = str(
                (raw.get("matcher") or {})
                .get("evidence_trace", {})
                .get("graph_path", "")
            )
        graph = Path(graph_ref)
        if not graph.is_absolute():
            graph = (
                Path(raw.get("benchmark", report_path.parent)).resolve().parent / graph
            ).resolve()
        try:
            result = replay_stored_report(raw, graph, pat)
        except Exception as exc:
            result = {"status": "FAIL", "errors": [str(exc)]}
        if result.get("status") == "PASS":
            passed += 1
        else:
            errors.append({"report": str(report_path), **result})
    return {
        "status": "PASS" if not errors else "FAIL",
        "validated_cases": len(reports),
        "passed_cases": passed,
        "failed_cases": len(errors),
        "errors": errors[:100],
        "validation_mode": "stored-fixed-binding-replay",
    }


def run_research_evaluation(
    root: str | Path,
    profile: str | Path,
    *,
    hidden_root: str | Path | None = None,
    out: str | Path | None = None,
    enforce_gates: bool = False,
    hidden_key_env: str | None = None,
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    profile_raw = load_profile(profile)
    base = run_research_check(
        rootp,
        profile,
        hidden_root=hidden_root,
        enforce_gates=enforce_gates,
        require_hidden=bool(profile_raw.get("require_hidden_validation", False)),
        hidden_key_env=hidden_key_env,
    )
    hidden_policy = profile_raw.get("hidden_policy") or {}
    hidden_sealed_required = bool(
        hidden_root
        and (
            profile_raw.get("require_hidden_validation", False)
            or profile_raw.get("require_hidden_hmac", False)
            or hidden_policy.get("require_external_origin", False)
        )
    )
    hidden_root_path = Path(hidden_root).resolve() if hidden_root else None
    hidden_gate_blocked = bool(
        hidden_sealed_required
        and (
            not hidden_root_path
            or not (hidden_root_path / "seal.json").is_file()
            or (base.get("hidden_integrity") or {}).get("status") != "PASS"
        )
    )
    family_reports = []
    for fam in sorted(rootp.glob("families/*")):
        pp = fam / "pattern.json"
        bp = fam / "benchmark.json"
        if not pp.is_file() or not bp.is_file():
            continue
        ev_dir = rootp / "reports" / "evaluations" / fam.name
        evaluation = evaluate_benchmark(
            bp,
            pp,
            ev_dir,
            replay=True,
            performance_repeats=int(
                profile_raw.get("performance", {}).get("repeats", 1) or 1
            ),
            max_case_seconds=profile_raw.get("performance", {}).get("max_case_seconds"),
            max_case_memory_bytes=profile_raw.get("performance", {}).get(
                "max_case_memory_bytes"
            ),
        )
        q = quality_audit(
            bp,
            min_case_count=int(
                (profile_raw.get("gates", {}) or {}).get("min_total", 0)
            ),
            min_positive=int(
                (profile_raw.get("gates", {}) or {}).get("min_positive", 0)
            ),
            min_negative=int(
                (profile_raw.get("gates", {}) or {}).get("min_negative", 0)
            ),
            min_unknown=int((profile_raw.get("gates", {}) or {}).get("min_unknown", 0)),
            min_real_world=int(profile_raw.get("min_real_world_cases", 0) or 0),
            required_dimensions=set(
                map(str, profile_raw.get("required_dimensions", []))
            ),
            dimension_minima={
                str(k): int(v)
                for k, v in (profile_raw.get("dimension_minima", {}) or {}).items()
            },
            min_dataset_sources=int(profile_raw.get("min_dataset_sources", 0) or 0),
            min_repositories=int(profile_raw.get("min_repositories", 0) or 0),
            min_projects=int(profile_raw.get("min_projects", 0) or 0),
            min_cves=int(profile_raw.get("min_cves", 0) or 0),
            require_split_strategies=set(
                map(str, profile_raw.get("required_split_strategies", []))
            ),
            require_label_provenance=bool(
                profile_raw.get("require_label_provenance", False)
            ),
            require_case_identity=bool(profile_raw.get("require_case_identity", False)),
            min_real_world_label_authority=int(
                profile_raw.get("min_real_world_label_authority", 0) or 0
            ),
        )
        evaluation["benchmark_meta"]["quality_audit"] = q
        family_report = {
            "family": fam.name,
            "quality": q,
            "evaluation": evaluation,
            "gates": validate_benchmark_gate(
                evaluation["metrics"],
                evaluation["benchmark_meta"],
                profile_raw,
                hidden=False,
            ),
        }
        if hidden_root and not hidden_gate_blocked:
            hb_candidates = [
                Path(hidden_root).resolve() / fam.name / "benchmark.json",
                Path(hidden_root).resolve() / "benchmark.json",
            ]
            hb = next((x for x in hb_candidates if x.is_file()), None)
            if hb:
                hev_dir = rootp / "reports" / "evaluations" / "hidden" / fam.name
                hidden_eval = evaluate_benchmark(
                    hb,
                    pp,
                    hev_dir,
                    replay=True,
                    performance_repeats=int(
                        profile_raw.get("performance", {}).get("repeats", 1) or 1
                    ),
                )
                hidden_q = quality_audit(
                    hb,
                    min_case_count=int(
                        (profile_raw.get("gates", {}) or {}).get("min_total", 0)
                    ),
                    min_positive=int(
                        (profile_raw.get("gates", {}) or {}).get("min_positive", 0)
                    ),
                    min_negative=int(
                        (profile_raw.get("gates", {}) or {}).get("min_negative", 0)
                    ),
                    min_unknown=int(
                        (profile_raw.get("gates", {}) or {}).get("min_unknown", 0)
                    ),
                    min_real_world=int(profile_raw.get("min_real_world_cases", 0) or 0),
                    required_dimensions=set(
                        map(str, profile_raw.get("required_dimensions", []))
                    ),
                    dimension_minima={
                        str(k): int(v)
                        for k, v in (
                            profile_raw.get("dimension_minima", {}) or {}
                        ).items()
                    },
                    min_dataset_sources=int(
                        profile_raw.get("min_dataset_sources", 0) or 0
                    ),
                    min_repositories=int(profile_raw.get("min_repositories", 0) or 0),
                    min_projects=int(profile_raw.get("min_projects", 0) or 0),
                    min_cves=int(profile_raw.get("min_cves", 0) or 0),
                    require_split_strategies=set(
                        map(str, profile_raw.get("required_split_strategies", []))
                    ),
                    require_label_provenance=bool(
                        profile_raw.get("require_label_provenance", False)
                    ),
                    require_case_identity=bool(
                        profile_raw.get("require_case_identity", False)
                    ),
                    min_real_world_label_authority=int(
                        profile_raw.get("min_real_world_label_authority", 0) or 0
                    ),
                )
                hidden_eval["benchmark_meta"]["quality_audit"] = hidden_q
                family_report["hidden_evaluation"] = hidden_eval
                family_report["hidden_quality"] = hidden_q
                family_report["hidden_gates"] = validate_benchmark_gate(
                    hidden_eval["metrics"],
                    hidden_eval["benchmark_meta"],
                    profile_raw,
                    hidden=True,
                )
            else:
                family_report["hidden_evaluation"] = None
                family_report["hidden_gates"] = [
                    "hidden benchmark not found for family"
                ]
        family_reports.append(family_report)
    result = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-research-evaluation",
        "tool_version": __version__,
        "root": str(rootp),
        "profile": str(Path(profile).resolve()),
        "base_research_check": base,
        "families": family_reports,
        "status": "PASS"
        if base.get("status") == "PASS"
        and all(
            not x["gates"]
            and not x.get("hidden_gates", [])
            and x["quality"]["status"] == "PASS"
            for x in family_reports
        )
        else "FAIL",
        "generated_at_utc": utc_now(),
    }
    result["evaluation_sha256"] = sha256_json(result)
    if out:
        _write_json(Path(out), result)
    return result
