from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Iterable

from .parsers import parse_graph
from .provenance import sha256_file

from . import SCHEMA_VERSION


def _safe_rel(base: Path, rel: str) -> Path:
    p = (base / rel).resolve()
    try:
        p.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact path escapes manifest root: {rel}") from exc
    return p


def _load(path: str | Path) -> tuple[Path, dict[str, Any]]:
    p = Path(path).resolve()
    return p, json.loads(p.read_text(encoding="utf-8"))


def _case_group(case: dict[str, Any], strategy: str) -> str | None:
    d = case.get("dataset") or {}
    if strategy == "repository":
        return str(d.get("repository") or d.get("repo") or "") or None
    if strategy == "project":
        return (
            str(d.get("project") or d.get("repository") or d.get("repo") or "") or None
        )
    if strategy == "cve":
        return str(d.get("cve") or d.get("CVE ID") or "") or None
    if strategy == "mutation":
        return str(case.get("mutation_of") or "") or None
    return str(case.get("id") or "") or None


def compose_benchmarks(
    inputs: Iterable[str | Path],
    out_manifest: str | Path,
    *,
    copy_graphs: bool = True,
    fail_on_conflicting_graph_label: bool = True,
    include_unknown: bool = True,
) -> dict[str, Any]:
    """Compose benchmark/dataset manifests without silently relabeling cases.

    Every graph referenced by an input manifest is copied into a deterministic output
    graph directory by default. Case IDs are made unique using the source manifest stem.
    Conflicting labels for identical graph digests are rejected.
    """
    out = Path(out_manifest).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    graph_dir = out.parent / (out.stem + ".graphs")
    if copy_graphs:
        graph_dir.mkdir(parents=True, exist_ok=True)

    datasets: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    digest_labels: dict[str, set[str]] = {}
    missing = 0

    for source in inputs:
        base, raw = _load(source)
        datasets.append(
            {
                "manifest": str(base),
                "dataset": raw.get("dataset")
                or raw.get("datasets")
                or raw.get("source_dataset")
                or {},
                "schema_version": raw.get("schema_version"),
            }
        )
        for original in raw.get("cases", []):
            if not isinstance(original, dict):
                continue
            expected = str(original.get("expected", "UNKNOWN")).upper()
            if expected not in {"MATCH", "NO_MATCH", "UNKNOWN"}:
                raise ValueError(f"invalid expected label in {base}: {expected}")
            if not include_unknown and expected == "UNKNOWN":
                continue
            graph_rel = original.get("graph")
            if not graph_rel:
                # Source-only manifests need graph capture before benchmark evaluation.
                clone = dict(original)
                cid = str(
                    clone.get("id")
                    or hashlib.sha256(
                        json.dumps(clone, sort_keys=True).encode()
                    ).hexdigest()[:16]
                )
                while cid in seen_ids:
                    cid = f"{base.stem}:{cid}"
                seen_ids.add(cid)
                clone["id"] = cid
                clone["capture_required"] = True
                clone["input_manifest"] = str(base)
                cases.append(clone)
                continue
            graph_path = _safe_rel(base.parent, str(graph_rel))
            if not graph_path.is_file():
                missing += 1
                raise ValueError(f"graph missing for {original.get('id')}: {graph_rel}")
            digest = parse_graph(graph_path).digest()
            digest_labels.setdefault(digest, set()).add(expected)
            cid = str(
                original.get("id")
                or hashlib.sha256(f"{base}:{graph_rel}".encode()).hexdigest()[:16]
            )
            if cid in seen_ids:
                cid = f"{base.stem}:{cid}"
                while cid in seen_ids:
                    cid = f"{base.stem}:{cid}"
            seen_ids.add(cid)
            clone = json.loads(json.dumps(original))
            clone["id"] = cid
            clone["graph_sha256"] = sha256_file(graph_path)
            clone.setdefault("source_manifest", str(base))
            if copy_graphs:
                digest_name = f"{hashlib.sha256((cid + ':' + digest).encode()).hexdigest()[:24]}.json"
                destination = graph_dir / digest_name
                if not destination.exists():
                    shutil.copy2(graph_path, destination)
                clone["graph"] = str(destination.relative_to(out.parent))
            cases.append(clone)

    conflicts = {d: sorted(v) for d, v in digest_labels.items() if len(v) > 1}
    if conflicts and fail_on_conflicting_graph_label:
        sample = next(iter(conflicts.items()))
        raise ValueError(
            f"same graph digest appears with conflicting labels: {sample[0]} -> {sample[1]}"
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-benchmark",
        "manifest_id": f"{out.stem}-{SCHEMA_VERSION}",
        "description": "Composed EvidenceLab benchmark; labels and source provenance preserved.",
        "datasets": datasets,
        "cases": cases,
        "composition": {
            "inputs": [str(Path(x).resolve()) for x in inputs],
            "copy_graphs": copy_graphs,
            "conflicting_graph_digests": conflicts,
            "missing_graphs": missing,
        },
    }
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS" if not conflicts else "WARN",
        "manifest": str(out),
        "case_count": len(cases),
        "graph_count": sum(1 for c in cases if c.get("graph")),
        "source_only_cases": sum(1 for c in cases if c.get("capture_required")),
        "conflicting_graphs": len(conflicts),
        "datasets": len(datasets),
    }


def benchmark_plan(
    manifest: str | Path,
    profile: dict[str, Any],
    *,
    quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce a deterministic, actionable readiness plan against a research profile.

    The plan distinguishes missing *cases*, *semantic dimensions*, *diversity*,
    *provenance*, and *evaluation protocol* so researchers know what evidence must be
    collected next instead of merely being told that a score is below a threshold.
    """
    p = Path(manifest).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    cases = [c for c in raw.get("cases", []) if isinstance(c, dict)]
    labels = {k: 0 for k in ("MATCH", "NO_MATCH", "UNKNOWN")}
    independent_labels = {k: 0 for k in ("MATCH", "NO_MATCH", "UNKNOWN")}
    dims = {}
    repos = set()
    projects = set()
    cves = set()
    sources = set()
    real_world = independent_real_world = mutation = 0
    independent_cases = [
        c
        for c in cases
        if not (c.get("mutation_of") or c.get("mutation_parent") or c.get("mutation"))
    ]
    for c in cases:
        exp = str(c.get("expected", "UNKNOWN")).upper()
        labels[exp] = labels.get(exp, 0) + 1
        ds = c.get("dataset") or {}
        if ds.get("name"):
            sources.add(str(ds["name"]))
        if ds.get("repository") or ds.get("repo"):
            repos.add(str(ds.get("repository") or ds.get("repo")))
        if ds.get("project"):
            projects.add(str(ds.get("project")))
        if ds.get("cve") or ds.get("CVE ID"):
            cves.add(str(ds.get("cve") or ds.get("CVE ID")))
        dd = set(str(x) for x in (c.get("dimensions") or [])) | set(
            str(x) for x in (c.get("tags") or [])
        )
        for d in dd:
            dims[d] = dims.get(d, 0) + 1
        canonical = set(dd)
        if "guard_dominance" in dd:
            canonical.add("control_conditions")
        if "incomplete_analysis" in dd:
            canonical.add("analysis_completeness")
        if dd & {
            "mutate_extent_only",
            "mutate_object_only",
            "mutate_analysis_completeness",
        }:
            canonical.add("mutation")
        if "real_world" in canonical:
            real_world += 1
        if c.get("mutation_of"):
            mutation += 1
    for c in independent_cases:
        exp = str(c.get("expected", "UNKNOWN")).upper()
        independent_labels[exp] = independent_labels.get(exp, 0) + 1
        dd = set(str(x) for x in (c.get("dimensions") or [])) | set(
            str(x) for x in (c.get("tags") or [])
        )
        canonical = set(dd)
        canonical.add("control_conditions") if "guard_dominance" in dd else None
        canonical.add("analysis_completeness") if "incomplete_analysis" in dd else None
        if "real_world" in canonical:
            independent_real_world += 1
    covered = set(dims)
    if "guard_dominance" in covered:
        covered.add("control_conditions")
    if "incomplete_analysis" in covered:
        covered.add("analysis_completeness")
    if covered & {
        "mutate_extent_only",
        "mutate_object_only",
        "mutate_analysis_completeness",
    }:
        covered.add("mutation")
    gates = profile.get("gates", {}) or {}
    required_dims = set(map(str, profile.get("required_dimensions", [])))
    split_meta = raw.get("split", {}) or {}
    strategies = set()
    if isinstance(split_meta, dict):
        if split_meta.get("strategy"):
            strategies.add(str(split_meta["strategy"]))
        strategies.update(str(x) for x in split_meta.get("strategies", []) if x)
    checks = []
    for ident, actual, required in [
        ("total", len(cases), int(gates.get("min_total", 0))),
        (
            "independent_total",
            len(independent_cases),
            int(gates.get("min_independent_total", 0) or 0),
        ),
        (
            "positive",
            independent_labels["MATCH"],
            int(gates.get("min_independent_positive", gates.get("min_positive", 0))),
        ),
        (
            "negative",
            independent_labels["NO_MATCH"],
            int(gates.get("min_independent_negative", gates.get("min_negative", 0))),
        ),
        (
            "unknown",
            independent_labels["UNKNOWN"],
            int(gates.get("min_independent_unknown", gates.get("min_unknown", 0))),
        ),
        (
            "real_world",
            independent_real_world,
            int(profile.get("min_real_world_cases", 0) or 0),
        ),
        (
            "dataset_sources",
            len(sources),
            int(profile.get("min_dataset_sources", 0) or 0),
        ),
        ("repositories", len(repos), int(profile.get("min_repositories", 0) or 0)),
        ("projects", len(projects), int(profile.get("min_projects", 0) or 0)),
        ("cves", len(cves), int(profile.get("min_cves", 0) or 0)),
        (
            "mutation",
            mutation,
            int((profile.get("dimension_minima", {}) or {}).get("mutation", 0)),
        ),
    ]:
        checks.append(
            {
                "id": ident,
                "actual": actual,
                "required": required,
                "ok": actual >= required,
            }
        )
    for d, want in (profile.get("dimension_minima", {}) or {}).items():
        checks.append(
            {
                "id": f"dimension:{d}",
                "actual": dims.get(d, 0),
                "required": int(want),
                "ok": dims.get(d, 0) >= int(want),
            }
        )
    gaps = [
        f"{x['id']}: {x['actual']} < {x['required']}" for x in checks if not x["ok"]
    ]
    gaps += [
        f"dimension:{d}: missing entirely" for d in sorted(required_dims - covered)
    ]
    required_splits = set(map(str, profile.get("required_split_strategies", [])))
    gaps += [f"split:{x}: not declared" for x in sorted(required_splits - strategies)]
    if profile.get("require_hidden_validation") and not (
        raw.get("hidden")
        or raw.get("hidden_validation")
        or raw.get("partition") == "hidden"
    ):
        gaps.append("hidden_validation: evaluator-controlled hidden benchmark required")
    if profile.get("require_real_world_validation") and real_world == 0:
        gaps.append("real_world: no real-world cases represented")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not gaps else "FAIL",
        "manifest": str(p),
        "counts": {
            "cases": len(cases),
            "independent_cases": len(independent_cases),
            "labels": labels,
            "independent_labels": independent_labels,
            "dimensions": dims,
            "real_world": real_world,
            "independent_real_world": independent_real_world,
            "mutation": mutation,
            "repositories": len(repos),
            "projects": len(projects),
            "cves": len(cves),
            "dataset_sources": len(sources),
            "split_strategies": sorted(strategies),
        },
        "required": {
            "gates": gates,
            "dimensions": sorted(required_dims),
            "dimension_minima": profile.get("dimension_minima", {}),
            "required_split_strategies": sorted(required_splits),
        },
        "checks": checks,
        "gaps": gaps,
        "quality": quality,
    }
