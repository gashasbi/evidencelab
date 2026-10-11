from __future__ import annotations
from pathlib import Path
from typing import Any
import json
import math
from .audit import audit_pattern
from .spec import Pattern
from . import SCHEMA_VERSION
from .failure_taxonomy import classify_errors


def load_profile(path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("profile must be an object")
    return raw


def validate_profile(pattern: Pattern, profile: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    task = profile.get("task", {})
    expected = str(task.get("cwe", "ANY")).upper()
    current_schema = str(pattern.schema_version)
    if (
        profile.get("require_analyzer_independent_patterns")
        and current_schema != SCHEMA_VERSION
    ):
        errors.append(
            f"analyzer-independent publication patterns must use the current schema, got {current_schema}"
        )
    if expected != "ANY" and expected != pattern.cwe:
        errors.append(f"pattern CWE {pattern.cwe} does not match task {expected}")
    for finding in audit_pattern(pattern, profile.get("audit", {})):
        if finding.severity == "ERROR":
            errors.append(f"{finding.id}: {finding.message}")
    for field in profile.get("required_metadata", []):
        if field not in pattern.metadata:
            errors.append(f"missing required metadata: {field}")
    actual = {c.kind for c in pattern.claims if c.required}
    required_kinds = set(profile.get("required_claim_kinds", []))
    for kind in sorted(required_kinds - actual):
        errors.append(f"required claim kind missing: {kind}")
    return errors


def validate_benchmark_gate(
    metrics: dict[str, Any],
    meta: dict[str, Any],
    profile: dict[str, Any],
    hidden: bool = False,
) -> list[str]:
    errors: list[str] = []
    gates = profile.get("gates", {}) or {}
    total = int(metrics.get("total", 0))
    known = int(metrics.get("known", 0))
    if total < int(gates.get("min_total", 0)):
        errors.append(f"total cases below minimum: {total} < {gates.get('min_total')}")
    audit_for_counts = (
        meta.get("quality_audit", {}) or meta.get("benchmark_audit", {}) or {}
    )
    independent_total = int(audit_for_counts.get("independent_case_count", total) or 0)
    independent_labels = audit_for_counts.get("independent_label_counts", {}) or {}
    if independent_total < int(gates.get("min_independent_total", 0)):
        errors.append(
            f"independent cases below minimum: {independent_total} < {gates.get('min_independent_total')}"
        )
    if int(independent_labels.get("MATCH", 0)) < int(
        gates.get("min_independent_positive", 0)
    ):
        errors.append("independent positive corpus too small")
    if int(independent_labels.get("NO_MATCH", 0)) < int(
        gates.get("min_independent_negative", 0)
    ):
        errors.append("independent negative corpus too small")
    if int(independent_labels.get("UNKNOWN", 0)) < int(
        gates.get("min_independent_unknown", 0)
    ):
        errors.append("independent unknown corpus too small")
    if int(metrics.get("tp", 0)) + int(metrics.get("fn", 0)) < int(
        gates.get("min_positive", 0)
    ):
        errors.append("positive corpus too small")
    if int(metrics.get("tn", 0)) + int(metrics.get("fp", 0)) < int(
        gates.get("min_negative", 0)
    ):
        errors.append("negative corpus too small")
    if int(gates.get("min_unknown", 0)) > 0 and int(
        metrics.get("expected_unknown", 0)
    ) < int(gates.get("min_unknown")):
        errors.append("unknown corpus too small")
    if known <= 0:
        errors.append("benchmark contains no known-labeled cases")
    if int(metrics.get("infra_errors", 0) or 0) > 0:
        errors.append(
            f"analyzer/resource infrastructure errors present: {metrics.get('infra_errors')}"
        )

    for key in ("precision", "recall", "f1", "specificity", "balanced_accuracy", "mcc"):
        want = gates.get("min_" + key)
        if want is not None and (
            metrics.get(key) is None or metrics[key] < float(want)
        ):
            errors.append(f"{key} gate failed: {metrics.get(key)} < {want}")
    want = gates.get("max_false_positive_rate")
    if want is not None and (
        metrics.get("false_positive_rate") is None
        or metrics["false_positive_rate"] > float(want)
    ):
        errors.append(
            f"false_positive_rate gate failed: {metrics.get('false_positive_rate')} > {want}"
        )

    # Confidence intervals matter for research claims: a point estimate of 1.0 from a
    # small corpus must not automatically satisfy a publication gate.
    ci_minima = gates.get("min_ci_lower_bounds", {}) or {}
    ci_map = {
        "precision": "precision_ci95",
        "recall": "recall_ci95",
        "specificity": "specificity_ci95",
        "false_positive_rate": "false_positive_rate_ci95",
        "false_negative_rate": "false_negative_rate_ci95",
    }
    cluster_ci = (
        (meta.get("cluster_statistics") or {}).get("classification") or {}
    ).get("ci95") or {}
    use_cluster = bool(profile.get("require_cluster_aware_statistics")) and bool(
        cluster_ci
    )
    for metric_name, required_lower in ci_minima.items():
        key = ci_map.get(str(metric_name), str(metric_name))
        ci = (cluster_ci.get(str(metric_name)) if use_cluster else None) or metrics.get(
            key
        )
        label = f"cluster-aware {metric_name}" if use_cluster else str(metric_name)
        valid_ci = (
            isinstance(ci, list)
            and len(ci) == 2
            and all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in ci)
        )
        actual = ci[0] if valid_ci else None
        if (not valid_ci) or actual < float(required_lower):
            if actual is None:
                errors.append(
                    f"{label} CI lower-bound gate unavailable: a valid two-sided CI is required (minimum lower bound {required_lower})"
                )
            else:
                errors.append(
                    f"{label} CI lower-bound gate failed: {actual} < {required_lower}"
                )

    required_dims = set(map(str, profile.get("required_dimensions", [])))
    coverage = meta.get("coverage_by_tag", {}) or {}
    audit_meta = meta.get("benchmark_audit", {}) or {}
    dim_counts = (
        meta.get("dimension_counts") or audit_meta.get("dimension_counts") or coverage
    )
    covered = {str(k) for k, v in dim_counts.items() if int(v or 0) > 0}
    aliases = {
        "guard_dominance": "control_conditions",
        "incomplete_analysis": "analysis_completeness",
        "mutate_analysis_completeness": "mutation",
        "mutate_extent_only": "mutation",
        "mutate_object_only": "mutation",
        "real_corpus": "real_world",
    }
    covered |= {aliases.get(str(x), str(x)) for x in list(covered)}
    for x in sorted(required_dims - covered):
        errors.append(f"required benchmark dimension missing: {x}")
    for d, want in (profile.get("dimension_minima", {}) or {}).items():
        got = int(dim_counts.get(d, 0) or 0)
        got = max(
            got,
            int(
                dim_counts.get(next((k for k, v in aliases.items() if v == d), ""), 0)
                or 0
            ),
        )
        if got < int(want):
            errors.append(f"dimension minimum failed: {d}: {got} < {want}")
    qa = meta.get("quality_audit") or {}
    semantic = qa.get("semantic_diversity") or {}
    if profile.get("min_semantic_independence_ratio") is not None:
        ratio = semantic.get("effective_semantic_sample_size")
        total_sem = semantic.get("graph_count")
        ratio = (float(ratio) / float(total_sem)) if total_sem else 0.0
        if ratio < float(profile["min_semantic_independence_ratio"]):
            errors.append(
                f"semantic independence ratio below minimum: {ratio} < {profile['min_semantic_independence_ratio']}"
            )
    if profile.get("min_independence_clusters") is not None:
        clusters = int((qa.get("independence_clusters") or {}).get("count", 0) or 0)
        if clusters < int(profile["min_independence_clusters"]):
            errors.append(
                f"independence cluster minimum failed: {clusters} < {profile['min_independence_clusters']}"
            )
    if profile.get("require_cluster_aware_statistics") and not meta.get(
        "cluster_statistics"
    ):
        errors.append("cluster-aware statistics are required")

    audit = meta.get("benchmark_audit", {}) or {}
    canonical = audit.get("canonical_graph", {}) or {}
    if profile.get("require_canonical_graph", False):
        if canonical.get("status") != "PASS":
            errors.append(
                "canonical graph preparation is required for every benchmark case"
            )
    if profile.get("require_unique_graphs", True) and audit.get("warnings"):
        errors.append("benchmark audit produced warnings under uniqueness policy")
    if audit.get("status") == "FAIL":
        errors.extend([f"benchmark audit: {x}" for x in audit.get("errors", [])])

    if profile.get("require_hidden_validation", False) and not hidden:
        errors.append("hidden validation required")
    if (
        profile.get("require_hidden_hmac", False)
        and hidden
        and not (meta.get("hidden_integrity") or {}).get("hmac_present", False)
    ):
        errors.append("hidden validation must be HMAC sealed under this profile")
    real_count = int(audit.get("real_world_cases", 0) or 0)
    if profile.get("require_real_world_validation", False) and real_count <= 0:
        errors.append("real-world validation required")
    if profile.get("min_real_world_cases") is not None and real_count < int(
        profile["min_real_world_cases"]
    ):
        errors.append(
            f"real-world case minimum failed: {real_count} < {profile['min_real_world_cases']}"
        )
    for key, minimum in {
        "dataset_source_count": "min_dataset_sources",
        "repository_count": "min_repositories",
        "project_count": "min_projects",
        "cve_count": "min_cves",
    }.items():
        if profile.get(minimum) is not None and int(audit.get(key, 0) or 0) < int(
            profile[minimum]
        ):
            errors.append(
                f"{minimum} failed: {int(audit.get(key, 0) or 0)} < {profile[minimum]}"
            )
    required_splits = set(map(str, profile.get("required_split_strategies", [])))
    split_meta = audit.get("split_metadata", {}) or {}
    declared = set()
    if isinstance(split_meta, dict):
        if split_meta.get("strategy"):
            declared.add(str(split_meta["strategy"]))
        declared.update(str(x) for x in split_meta.get("strategies", []) if x)
    if required_splits and not required_splits.issubset(declared):
        errors.append(
            "required benchmark split strategies not all declared: "
            + ", ".join(sorted(required_splits - declared))
        )
    if hidden and int(meta.get("partitions", {}).get("hidden", 0)) == 0:
        errors.append("hidden benchmark has no hidden cases")
    if profile.get("max_actual_partial") is not None and int(
        metrics.get("actual_partial", 0)
    ) > int(profile["max_actual_partial"]):
        errors.append(
            f"actual PARTIAL count exceeds gate: {metrics.get('actual_partial')} > {profile['max_actual_partial']}"
        )
    if (
        profile.get("require_independent_witness_validation", False)
        and meta.get("witness_validation", {}).get("status") != "PASS"
    ):
        errors.append("independent witness validation required")
    if profile.get("require_failure_taxonomy", False):
        taxonomy = meta.get("failure_taxonomy") or {}
        if not taxonomy.get("definitions"):
            errors.append("failure taxonomy is required")
    q = meta.get("evidence_quality") or {}
    if profile.get("performance") and profile.get("require_performance_evaluation"):
        perf = meta.get("performance") or {}
        if not perf:
            errors.append("performance evaluation is required")
        else:
            lim = perf.get("limits") or {}
            if lim.get("violations"):
                errors.append("performance resource/time limit violations present")
            if int(lim.get("infra_errors", 0) or 0) > 0:
                errors.append("performance evaluation recorded infrastructure errors")
            p = profile.get("performance") or {}
            p99 = (perf.get("case_seconds") or {}).get("p99")
            max_case = p.get("max_case_seconds")
            if (
                max_case is not None
                and p99 is not None
                and float(p99) > float(max_case)
            ):
                errors.append(
                    f"performance p99 exceeds max_case_seconds: {p99} > {max_case}"
                )
            max_mem = p.get("max_case_memory_bytes")
            observed = (perf.get("resource") or {}).get("max_case_peak_rss_bytes")
            if (
                max_mem is not None
                and observed is not None
                and int(observed) > int(max_mem)
            ):
                errors.append(f"performance memory gate failed: {observed} > {max_mem}")
    for name, want in (profile.get("evidence_quality_gates", {}) or {}).items():
        val = q.get(name)
        if val is None or float(val) < float(want):
            errors.append(f"evidence quality gate failed: {name}: {val} < {want}")
    return errors
