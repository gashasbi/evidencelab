from __future__ import annotations
from pathlib import Path
from typing import Any
import json
from .leakage import audit_benchmark_lineage
from .canonical import SEMANTIC_FINGERPRINT_ALGORITHM, semantic_graph_fingerprint

RECOMMENDED_CASE_DIMENSIONS = {
    "positive",
    "negative",
    "unknown",
    "counter_evidence",
    "adversarial",
    "dataflow",
    "object_identity",
    "control_conditions",
    "analysis_completeness",
    "interprocedural",
    "cross_file",
    "real_corpus",
    "real_world",
    "mutation",
}
ALIASES = {
    "guard_dominance": "control_conditions",
    "incomplete_analysis": "analysis_completeness",
    "mutate_extent_only": "mutation",
    "mutate_object_only": "mutation",
    "mutate_analysis_completeness": "mutation",
}


def _case_dimensions(case: dict[str, Any]) -> set[str]:
    # Normalize aliases in both metadata channels. Otherwise the same semantic
    # dimension can be counted differently depending on whether it was recorded
    # as a tag or in the explicit dimensions list.
    tags = {ALIASES.get(str(x), str(x)) for x in case.get("tags", [])}
    dimensions = (
        {ALIASES.get(str(x), str(x)) for x in case.get("dimensions", [])}
        if isinstance(case.get("dimensions"), list)
        else set()
    )
    out = dimensions | tags
    expected = str(case.get("expected", "UNKNOWN")).upper()
    if expected == "MATCH":
        out.add("positive")
    elif expected == "NO_MATCH":
        out.add("negative")
    else:
        out.add("unknown")
    return out

def _real_world_identity(case: dict[str, Any]) -> tuple[bool, list[str]]:
    dataset = case.get("dataset") or {}
    missing = []
    if not dataset.get("name"):
        missing.append("dataset.name")
    if not (dataset.get("repository") or dataset.get("repo") or dataset.get("project")):
        missing.append("dataset.repository/project")
    if not (
        dataset.get("commit")
        or dataset.get("commit_id")
        or dataset.get("revision")
        or dataset.get("commit_url")
    ):
        missing.append("dataset.commit")
    expected = str(case.get("expected", "UNKNOWN")).upper()
    has_issue = bool(
        dataset.get("cve")
        or dataset.get("CVE ID")
        or dataset.get("vulnerability_id")
        or dataset.get("issue_id")
        or case.get("cve")
        or dataset.get("vulnerability")
        or dataset.get("bug_id")
    )
    # A label's source is provenance, not evidence that an issue/patch exists.
    # Keep vulnerability identity and label provenance as separate requirements.
    has_patch = bool(
        dataset.get("patch_context")
        or dataset.get("patch_url")
        or case.get("counterpart")
        or dataset.get("vulnerable_commit")
        or dataset.get("pair_id")
    )
    if expected == "MATCH" and not (has_issue or has_patch):
        missing.append("dataset.cve/issue/vulnerability_id/patch_context")
    if not (
        dataset.get("provenance_url")
        or dataset.get("source_url")
        or dataset.get("commit_url")
        or case.get("source_url")
        or dataset.get("source")
    ):
        missing.append("dataset.provenance_url/source")
    return not missing, missing

def _is_mutation(case: dict[str, Any]) -> bool:
    return bool(
        case.get("mutation_of") or case.get("mutation_parent") or case.get("mutation")
    )


def _is_independent(case: dict[str, Any]) -> bool:
    # Count paired revisions; exclude only declared mutation descendants from independence gates.
    return not _is_mutation(case)


def _count_labels(cases: list[dict[str, Any]]) -> dict[str, int]:
    labels = {"MATCH": 0, "NO_MATCH": 0, "UNKNOWN": 0}
    for case in cases:
        exp = str(case.get("expected", "UNKNOWN")).upper()
        labels[exp] = labels.get(exp, 0) + 1
    return labels


def _count_dimensions(cases: list[dict[str, Any]]) -> dict[str, int]:
    dimensions: dict[str, int] = {}
    for case in cases:
        for d in _case_dimensions(case):
            dimensions[d] = dimensions.get(d, 0) + 1
    return dict(sorted(dimensions.items()))


def _semantic_diversity(
    manifest_path: Path, cases: list[dict[str, Any]]
) -> dict[str, Any]:
    try:
        from .parsers import parse_graph
        from .evaluator import _safe_case_path

        fingerprints = []
        graph_errors = []
        invalid_graphs = []
        graph_count = 0

        for case in cases:
            rel = case.get("graph")
            if not rel:
                continue

            case_id = str(case.get("id", "<unknown>"))
            try:
                g = parse_graph(_safe_case_path(manifest_path, str(rel)))
            except Exception as exc:
                graph_errors.append({
                    "case_id": case_id,
                    "graph": str(rel),
                    "error": str(exc),
                })
                continue

            health = str(g.metadata.get("parse_health", "UNKNOWN")).upper()
            if health == "INVALID" or (not g.nodes and not g.edges):
                invalid_graphs.append({
                    "case_id": case_id,
                    "graph": str(rel),
                    "parse_health": health,
                    "reason": (
                        "parser marked graph INVALID"
                        if health == "INVALID"
                        else "graph contains no nodes or edges"
                    ),
                })
                continue

            fingerprints.append(semantic_graph_fingerprint(g))
            graph_count += 1

        unique = len(set(fingerprints))
        return {
            "graph_count": graph_count,
            "unique_semantic_graphs": unique,
            "semantic_duplicate_rate": round(1.0 - unique / graph_count, 6)
            if graph_count
            else None,
            "effective_semantic_sample_size": unique,
            "semantic_fingerprint_algorithm": SEMANTIC_FINGERPRINT_ALGORITHM,
            "graph_errors": graph_errors,
            "invalid_graphs": invalid_graphs,
        }
    except Exception as exc:
        return {
            "graph_count": 0,
            "unique_semantic_graphs": 0,
            "semantic_duplicate_rate": None,
            "effective_semantic_sample_size": 0,
            "semantic_fingerprint_algorithm": SEMANTIC_FINGERPRINT_ALGORITHM,
            "graph_errors": [],
            "invalid_graphs": [],
            "error": str(exc),
        }


DIMENSION_TAXONOMY = {
    "dataflow": {
        "class": "semantic",
        "definition": "A source/value is connected to a sink through data-flow evidence.",
        "independence_rule": "Must differ by semantic scenario, not merely node IDs.",
    },
    "object_identity": {
        "class": "semantic",
        "definition": "The witness destination and capacity refer to the same memory object.",
        "independence_rule": "Alias/reassignment/field/heap scenarios count separately only when semantic structure differs.",
    },
    "control_conditions": {
        "class": "control",
        "definition": "A guard, validation, dominance or post-dominance relation materially changes the witness outcome.",
        "independence_rule": "Guard placement/condition semantics must differ.",
    },
    "analysis_completeness": {
        "class": "analysis",
        "definition": "Controlled complete/partial/missing analyzer evidence is used to test uncertainty semantics.",
        "independence_rule": "Completeness state and affected analysis dimension must be explicit.",
    },
    "interprocedural": {
        "class": "semantic",
        "definition": "Witness crosses a function boundary.",
        "independence_rule": "Distinct call/return or summary topology required.",
    },
    "cross_file": {
        "class": "semantic",
        "definition": "Witness crosses a source-file boundary.",
        "independence_rule": "Distinct file identity must participate in the witness.",
    },
    "real_world": {
        "class": "dataset",
        "definition": "Case is derived from an external real-world corpus with traceable identity/label authority.",
        "independence_rule": "Not a copied synthetic fixture.",
    },
    "mutation": {
        "class": "lineage",
        "definition": "A controlled one-change perturbation used to test evidence sensitivity.",
        "independence_rule": "Descendants do not increase independent sample size.",
    },
    "provenance": {
        "class": "provenance",
        "definition": "Case/fact/evidence lineage is traceable to artifacts, queries and authoritative labels.",
        "independence_rule": "Provenance metadata must be case-specific and hashable.",
    },
}


def quality_audit(
    manifest: str | Path,
    min_case_count: int = 120,
    min_positive: int = 40,
    min_negative: int = 40,
    min_unknown: int = 20,
    min_real_world: int = 0,
    required_dimensions: set[str] | None = None,
    require_group_metadata: bool = True,
    dimension_minima: dict[str, int] | None = None,
    min_dataset_sources: int = 0,
    min_repositories: int = 0,
    min_projects: int = 0,
    min_cves: int = 0,
    require_split_strategies: set[str] | None = None,
    require_label_provenance: bool = False,
    require_case_identity: bool = False,
    min_real_world_label_authority: int = 0,
    require_negative_basis: bool = False,
    require_source_similarity_audit: bool = False,
    source_similarity_threshold: float = 0.92,
) -> dict[str, Any]:
    p = Path(manifest).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    cases = raw.get("cases", [])
    errors = []
    warnings = []
    if not isinstance(cases, list):
        return {
            "status": "FAIL",
            "errors": ["cases must be an array"],
            "warnings": [],
            "case_count": 0,
        }
    independent = [c for c in cases if isinstance(c, dict) and _is_independent(c)]
    mutation_cases = [
        c for c in cases if isinstance(c, dict) and not _is_independent(c)
    ]
    labels = _count_labels(cases)
    independent_labels = _count_labels(independent)
    dimensions = _count_dimensions(cases)
    independent_dimensions = _count_dimensions(independent)
    sources = {}
    repositories = set()
    projects = set()
    cves = set()
    digests = set()
    real_world_count = 0
    independent_real_world_count = 0
    authoritative_real_world_labels = 0
    invalid = []
    provenance_invalid = []
    identity_invalid = []
    negative_basis_invalid = []
    for case in cases:
        expected = str(case.get("expected", "UNKNOWN")).upper()
        ds = case.get("dataset", {}) or {}
        if ds.get("name"):
            sources[str(ds["name"])] = sources.get(str(ds["name"]), 0) + 1
        repo = ds.get("repository") or ds.get("repo")
        project = ds.get("project")
        if repo:
            repositories.add(str(repo))
        if project:
            projects.add(str(project))
        cve = ds.get("cve") or ds.get("CVE ID")
        if cve:
            if isinstance(cve, list):
                cves.update(str(x) for x in cve)
            else:
                cves.add(str(cve))
        if require_negative_basis and expected == "NO_MATCH":
            basis = (
                case.get("negative_evidence")
                or case.get("safe_basis")
                or case.get("counter_evidence_basis")
            )
            if not basis:
                negative_basis_invalid.append(str(case.get("id", "<unknown>")))
        if require_label_provenance and expected in {"MATCH", "NO_MATCH"}:
            lp = case.get("label_provenance") or {}
            authority = str(lp.get("authority") if isinstance(lp, dict) else "").upper()
            source = (
                (lp.get("source") if isinstance(lp, dict) else None)
                or case.get("label_source")
                or ds.get("label_source")
            )
            if (
                authority
                not in {"AUTHORITATIVE", "DATASET", "HUMAN", "PATCH_BASED", "EXPLICIT"}
                or not source
            ):
                provenance_invalid.append(str(case.get("id", "<unknown>")))
        if require_case_identity:
            ident = case.get("case_identity") or {}
            stable = (
                (
                    ident.get("record_id")
                    or ident.get("pair_id")
                    or ident.get("source_sha256")
                    or ident.get("normalized_source_hash")
                    or case.get("source_content_sha256")
                    or case.get("source_sha256")
                    or ds.get("record_id")
                    or case.get("id")
                )
                if isinstance(ident, dict)
                else (case.get("source_sha256") or case.get("id"))
            )
            if not stable:
                identity_invalid.append(str(case.get("id", "<unknown>")))
        dims = _case_dimensions(case)
        if "real_world" in dims:
            real_world_count += 1
            if _is_independent(case):
                independent_real_world_count += 1
            ok, missing = _real_world_identity(case)
            if not ok:
                invalid.append(
                    {"id": str(case.get("id", "<unknown>")), "missing": missing}
                )
            lp = case.get("label_provenance") or {}
            authority = str(lp.get("authority") if isinstance(lp, dict) else "").upper()
            if (
                _is_independent(case)
                and authority in {"AUTHORITATIVE", "DATASET", "HUMAN", "PATCH_BASED"}
                and expected in {"MATCH", "NO_MATCH"}
            ):
                authoritative_real_world_labels += 1
        if case.get("graph_sha256"):
            digests.add(str(case["graph_sha256"]))
    if len(cases) < min_case_count:
        errors.append(f"total cases below minimum: {len(cases)} < {min_case_count}")
    if independent_labels["MATCH"] < min_positive:
        errors.append(
            f"independent positive corpus too small: {independent_labels['MATCH']} < {min_positive}"
        )
    if independent_labels["NO_MATCH"] < min_negative:
        errors.append(
            f"independent negative corpus too small: {independent_labels['NO_MATCH']} < {min_negative}"
        )
    if independent_labels["UNKNOWN"] < min_unknown:
        errors.append(
            f"independent unknown corpus too small: {independent_labels['UNKNOWN']} < {min_unknown}"
        )
    if invalid:
        errors.append(
            f"real-world cases missing provenance/identity metadata: {len(invalid)}"
        )
    if provenance_invalid:
        errors.append(
            f"label provenance missing/weak on {len(provenance_invalid)} known cases"
        )
    if identity_invalid:
        errors.append(f"case identity missing on {len(identity_invalid)} cases")
    if negative_basis_invalid:
        errors.append(
            f"negative evidence basis missing on {len(negative_basis_invalid)} NO_MATCH cases"
        )
    if authoritative_real_world_labels < int(min_real_world_label_authority):
        errors.append(
            f"authoritative real-world labels below minimum: {authoritative_real_world_labels} < {min_real_world_label_authority}"
        )
    if independent_real_world_count < min_real_world:
        errors.append(
            f"independent real-world case minimum failed: {independent_real_world_count} < {min_real_world}"
        )
    if len(sources) < min_dataset_sources and cases:
        errors.append(
            f"dataset source diversity below minimum: {len(sources)} < {min_dataset_sources}"
        )
    if len(repositories) < min_repositories:
        errors.append(
            f"repository diversity below minimum: {len(repositories)} < {min_repositories}"
        )
    if len(projects) < min_projects:
        errors.append(
            f"project diversity below minimum: {len(projects)} < {min_projects}"
        )
    if len(cves) < min_cves:
        errors.append(f"CVE diversity below minimum: {len(cves)} < {min_cves}")
    minima = dimension_minima or {}
    for d, want in minima.items():
        got = dimensions.get(str(d), 0)
        if got < int(want):
            errors.append(f"dimension minimum failed: {d}: {got} < {want}")
    required = set(required_dimensions or ())
    missing = sorted(required - set(dimensions))
    if missing:
        errors.append("required benchmark dimensions missing: " + ", ".join(missing))
    for d in sorted(RECOMMENDED_CASE_DIMENSIONS - set(required)):
        if d not in dimensions:
            warnings.append(f"recommended benchmark dimension not represented: {d}")
    split_meta = raw.get("split", {}) or {}
    declared = set()
    if isinstance(split_meta, dict):
        if split_meta.get("strategy"):
            declared.add(str(split_meta["strategy"]))
        declared.update(str(x) for x in split_meta.get("strategies", []) if x)
    req_splits = set(require_split_strategies or ())
    if req_splits and not req_splits.issubset(declared):
        errors.append(
            "required benchmark split strategies not all declared: "
            + ", ".join(sorted(req_splits - declared))
        )
    if "chronological" in declared and not all(
        (c.get("dataset") or {}).get("date")
        or (c.get("dataset") or {}).get("commit_date")
        or c.get("date")
        or c.get("commit_date")
        for c in cases
    ):
        errors.append("chronological split metadata is incomplete")
    if require_group_metadata and real_world_count and not repositories:
        errors.append("real-world benchmark has no repository identity")
    if mutation_cases and not any(c.get("changed_dimension") for c in mutation_cases):
        errors.append(
            "mutation cases exist but no changed_dimension metadata is present"
        )
    lineage = audit_benchmark_lineage(p)
    if lineage["status"] != "PASS":
        errors.extend(lineage["errors"])
    if len(digests) and len(digests) != len(
        [c for c in cases if c.get("graph_sha256")]
    ):
        warnings.append("graph_sha256 metadata is not unique across all cases")
    source_similarity_audit = {
        "status": "NOT_EVALUABLE",
        "files": 0,
        "errors": [],
        "warnings": [],
    }
    if require_source_similarity_audit:
        from .leakage import audit_source_files

        source_paths = []
        for c in cases:
            src = c.get("source")
            if not src:
                continue
            try:
                candidate = (p.parent / str(src)).resolve()
                candidate.relative_to(p.parent.resolve())
                if candidate.is_file():
                    source_paths.append(candidate)
            except Exception:
                continue
        if source_paths:
            source_similarity_audit = audit_source_files(
                source_paths, similarity_threshold=float(source_similarity_threshold)
            )
            if source_similarity_audit.get("status") == "FAIL":
                errors.append("source similarity audit failed or was truncated")
            if source_similarity_audit.get(
                "exact_duplicate_groups"
            ) or source_similarity_audit.get("near_duplicates"):
                errors.append(
                    "source similarity audit detected exact/near duplicate source content"
                )
        else:
            errors.append(
                "source similarity audit is required but no source artifacts are available"
            )
    semantic = _semantic_diversity(p, cases)
    for graph_error in semantic.get("graph_errors", []):
        errors.append(
            "semantic graph unreadable for case "
            f"{graph_error['case_id']!r} "
            f"({graph_error['graph']}): {graph_error['error']}"
        )
    for invalid_graph in semantic.get("invalid_graphs", []):
        errors.append(
            "semantic graph invalid for case "
            f"{invalid_graph['case_id']!r} "
            f"({invalid_graph['graph']}): {invalid_graph['reason']}"
        )
    clusters = {}
    for c in independent:
        ds = c.get("dataset") or {}
        key = ds.get("repository") or ds.get("repo") or ds.get("project") or c.get("id")
        clusters[str(key)] = clusters.get(str(key), 0) + 1
    if independent and len(clusters) == 1 and len(independent) > 1:
        warnings.append(
            "all independent cases belong to one dependency cluster; confidence intervals should be cluster-aware"
        )
    return {
        "status": "FAIL" if errors else "PASS",
        "errors": errors,
        "warnings": warnings,
        "case_count": len(cases),
        "independent_case_count": len(independent),
        "mutation_cases": len(mutation_cases),
        "label_counts": labels,
        "independent_label_counts": independent_labels,
        "dimension_counts": dimensions,
        "independent_dimension_counts": independent_dimensions,
        "dataset_sources": sources,
        "dataset_source_count": len(sources),
        "repository_count": len(repositories),
        "project_count": len(projects),
        "cve_count": len(cves),
        "real_world_cases": real_world_count,
        "independent_real_world_cases": independent_real_world_count,
        "authoritative_real_world_labels": authoritative_real_world_labels,
        "invalid_real_world_cases": invalid[:100],
        "negative_basis_invalid": negative_basis_invalid[:100],
        "unique_declared_graph_hashes": len(digests),
        "mutation_lineage": lineage,
        "source_similarity_audit": source_similarity_audit,
        "split_metadata": raw.get("split", {}),
        "semantic_diversity": semantic,
        "independence_clusters": {
            "count": len(clusters),
            "sizes": sorted(clusters.values(), reverse=True),
        },
        "dimension_taxonomy": DIMENSION_TAXONOMY,
    }
