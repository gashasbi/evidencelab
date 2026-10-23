from __future__ import annotations
from . import SCHEMA_VERSION
from pathlib import Path
from typing import Any
import datetime
import hashlib
import os
import shutil
import json
import math
import re


def _required_group(case: dict[str, Any], strategy: str, allow_missing: bool) -> str:
    d = case.get("dataset", {}) or {}
    if strategy == "repository":
        value = d.get("repository") or d.get("repo") or case.get("repository")
    elif strategy == "project":
        value = (
            d.get("project")
            or d.get("repository")
            or d.get("repo")
            or case.get("project")
        )
    elif strategy == "cve":
        value = d.get("cve") or d.get("CVE ID") or case.get("cve")
    elif strategy == "mutation":
        value = case.get("mutation_of")
    else:
        value = case.get("id")
    if value:
        return str(value)
    if allow_missing:
        return f"__missing__:{case.get('id')}"
    raise ValueError(
        f"{strategy} split requires group metadata; missing for case {case.get('id')}"
    )


def _temporal_key(
    case: dict[str, Any], allow_missing: bool = False
) -> datetime.datetime:
    d = case.get("dataset", {}) or {}
    value = (
        d.get("date")
        or d.get("published")
        or d.get("commit_date")
        or case.get("date")
        or case.get("commit_date")
    )
    if not value:
        if allow_missing:
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        raise ValueError(
            f"chronological split requires date metadata; missing for case {case.get('id')}"
        )
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        m = re.match(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", text)
        if not m:
            raise ValueError(f"invalid date for case {case.get('id')}: {value}")
        dt = datetime.datetime(
            int(m.group(1)),
            int(m.group(2) or 1),
            int(m.group(3) or 1),
            tzinfo=datetime.timezone.utc,
        )
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _materialize_graphs(
    cases: list[dict[str, Any]], source_manifest: Path, out_dir: Path
) -> list[dict[str, Any]]:
    """Copy each partition's graph artifacts into a portable split directory.

    Each source graph belongs to exactly one partition, so materializing graphs does not
    multiply the corpus threefold. The emitted case keeps both file and canonical graph
    digests for later leakage/replay checks.
    """
    from .evaluator import _safe_case_path
    from .parsers import parse_graph

    prepared = []
    graph_dir = out_dir / "graphs"
    graph_dir.mkdir(parents=True, exist_ok=True)
    cache: dict[str, tuple[str, str]] = {}
    for case in cases:
        item = dict(case)
        rel = item.get("graph")
        if not rel:
            prepared.append(item)
            continue
        try:
            rel_text = str(rel)
            candidate = Path(rel_text)

            if candidate.is_absolute():
                raise PermissionError(f"absolute graph paths are forbidden: {rel_text}")
            gp = _safe_case_path(source_manifest, rel_text)
        except PermissionError:
            raise
        except ValueError as exc:
            message = str(exc)

            if (
                "graph_base escapes benchmark root" in message
                or "absolute graph_base is forbidden" in message
            ):
                raise PermissionError(message) from exc

            try:
                base = source_manifest.resolve().parent
                trusted = __import__(
                    "evidencelab.evaluator", fromlist=["_trusted_submission_root"]
                )._trusted_submission_root(source_manifest.resolve())
                candidate_path = (base / Path(rel_text)).resolve()
                allowed_roots = [base]
                raw_source = json.loads(source_manifest.read_text(encoding="utf-8"))
                graph_base = raw_source.get("graph_base")
                if graph_base and not Path(str(graph_base)).is_absolute():
                    allowed_roots.append((base / Path(str(graph_base))).resolve())
                if trusted != base:
                    for name in ("graphs", "graph_artifacts", "benchmarks", "evidence"):
                        allowed_roots.append((trusted / name).resolve())
                inside_allowed = any(
                    candidate_path == ar or ar in candidate_path.parents
                    for ar in allowed_roots
                )
            except Exception:
                inside_allowed = False
            if not inside_allowed and (
                Path(rel_text).parts and (".." in Path(rel_text).parts)
            ):
                raise PermissionError(message) from exc

            item.setdefault("split_warnings", []).append(message)
            prepared.append(item)
            continue
        key = str(gp.resolve())
        if key not in cache:
            file_hash = hashlib.sha256(gp.read_bytes()).hexdigest()
            dest_name = f"{file_hash[:16]}-{gp.name}"
            dst = graph_dir / dest_name
            if not dst.exists():
                shutil.copy2(gp, dst)
            canonical = parse_graph(gp).digest()
            cache[key] = (dest_name, canonical)
        dest_name, canonical = cache[key]
        item["graph"] = str(Path("graphs") / dest_name)
        item["graph_sha256"] = hashlib.sha256(
            (graph_dir / dest_name).read_bytes()
        ).hexdigest()
        item["canonical_graph_digest"] = canonical
        prepared.append(item)
    return prepared


def _partition_payload(
    raw: dict[str, Any],
    name: str,
    strategy: str,
    cases: list[dict[str, Any]],
    seed: str | None = None,
    *,
    split_dir: Path | None = None,
    source_manifest_parent: Path | None = None,
    source_manifest: Path | None = None,
) -> dict[str, Any]:
    payload = dict(raw)
    payload["schema_version"] = SCHEMA_VERSION
    payload["format"] = "evidencelab-benchmark"
    payload["split"] = {"name": name, "strategy": strategy}
    if seed is not None:
        payload["split"]["seed"] = seed
    if split_dir is not None and source_manifest_parent is not None:
        payload["split"]["source_manifest"] = str(
            (source_manifest or (source_manifest_parent / "benchmark.json")).resolve()
        )
        payload["split"]["graph_materialization"] = "copied"
    payload["cases"] = [dict(x, partition=name) for x in cases]
    return payload


def split_benchmark(
    manifest: str | Path,
    out_dir: str | Path,
    strategy: str = "repository",
    train: float = 0.6,
    validation: float = 0.2,
    test: float = 0.2,
    seed: str = "evidencelab-1.0.0",
    allow_missing_group: bool = False,
) -> dict[str, Any]:
    if abs(train + validation + test - 1.0) > 1e-6:
        raise ValueError("train+validation+test must equal 1")
    raw = json.loads(Path(manifest).read_text(encoding="utf-8"))
    cases = list(raw.get("cases", []))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[dict[str, Any]]] = {}
    case_map = {str(c.get("id")): c for c in cases}

    base_group: dict[str, str] = {}
    for case in cases:
        cid = str(case.get("id"))
        base_group[cid] = _required_group(case, strategy, allow_missing_group)

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for g in base_group.values():
        find(g)
    for case in cases:
        cid = str(case.get("id"))
        pcase = case.get("mutation_of") or case.get("mutation_parent")
        if pcase and str(pcase) in base_group:
            union(base_group[cid], base_group[str(pcase)])
        counterpart = case.get("counterpart")
        if counterpart and str(counterpart) in base_group:
            union(base_group[cid], base_group[str(counterpart)])
    pair_groups: dict[str, list[str]] = {}
    for case in cases:
        pair_id = case.get("pair_id") or (case.get("dataset") or {}).get("pair_id")
        if pair_id:
            pair_groups.setdefault(str(pair_id), []).append(str(case.get("id")))
    for members in pair_groups.values():
        for a, b in zip(members, members[1:]):
            union(base_group[a], base_group[b])

    for case in cases:
        gid = find(base_group[str(case.get("id"))])
        groups.setdefault(gid, []).append(case)

    requested_ratios = {
        "train": train,
        "validation": validation,
        "test": test,
    }
    target_case_counts = {
        name: len(cases) * ratio for name, ratio in requested_ratios.items()
    }
    buckets = {"train": [], "validation": [], "test": []}
    bucket_group_ids = {"train": [], "validation": [], "test": []}

    ordered = sorted(
        groups.items(),
        key=lambda kv: (
            -len(kv[1]),
            hashlib.sha256(f"{seed}:{kv[0]}".encode()).hexdigest(),
        ),
    )

    tie_priority = {"train": 0, "test": 1, "validation": 2}
    eligible_partitions = [
        name for name, ratio in requested_ratios.items() if ratio > 0
    ]

    for group_id, members in ordered:
        target = max(
            eligible_partitions,
            key=lambda name: (
                target_case_counts[name] - len(buckets[name]),
                tie_priority[name],
            ),
        )
        buckets[target].extend(members)
        bucket_group_ids[target].append(group_id)

    total_cases = len(cases)
    partition_case_ratios = {
        name: round(len(members) / total_cases, 6) if total_cases else 0.0
        for name, members in buckets.items()
    }
    partition_group_counts = {
        name: len(group_ids) for name, group_ids in bucket_group_ids.items()
    }
    case_ratio_deviation = {
        name: round(partition_case_ratios[name] - requested_ratios[name], 6)
        for name in buckets
    }

    quality_warnings = []
    for name in ("train", "validation", "test"):
        if requested_ratios[name] > 0 and partition_group_counts[name] < 2:
            quality_warnings.append(
                f"{name} partition has fewer than two indivisible groups "
                f"under {strategy} strategy; cluster-aware uncertainty "
                "is not estimable for this partition"
            )
        relative_ratio_deviation = (
            abs(case_ratio_deviation[name]) / requested_ratios[name]
            if requested_ratios[name] > 0
            else 0.0
        )
        if (
            total_cases
            and requested_ratios[name] > 0
            and (
                abs(case_ratio_deviation[name]) > 0.10
                or relative_ratio_deviation > 0.25
            )
        ):
            quality_warnings.append(
                f"{name} case ratio differs materially from its target "
                f"(absolute deviation={abs(case_ratio_deviation[name]):.3f}, "
                f"relative deviation={relative_ratio_deviation:.1%}); "
                "indivisible group sizes limit the requested ratio "
                "(diagnostic warning only)"
            )

    errors: list[str] = []
    owner: dict[str, str] = {}
    for name, members in buckets.items():
        for case in members:
            group = _required_group(case, strategy, allow_missing_group)
            if group in owner and owner[group] != name:
                errors.append(f"group leakage: {group} in {owner[group]} and {name}")
            owner[group] = name
        prepared = _materialize_graphs(
            sorted(members, key=lambda x: str(x.get("id"))),
            Path(manifest).resolve(),
            out,
        )
        payload = _partition_payload(
            raw,
            name,
            strategy,
            prepared,
            seed,
            split_dir=out,
            source_manifest_parent=Path(manifest).resolve().parent,
            source_manifest=Path(manifest).resolve(),
        )
        (out / f"{name}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return {
        "status": "PASS" if not errors else "FAIL",
        "strategy": strategy,
        "groups": len(groups),
        "cases": len(cases),
        "counts": {k: len(v) for k, v in buckets.items()},
        "partition_group_counts": partition_group_counts,
        "partition_case_ratios": partition_case_ratios,
        "target_case_ratios": {
            name: round(value, 6) for name, value in requested_ratios.items()
        },
        "case_ratio_deviation": case_ratio_deviation,
        "quality_warnings": quality_warnings,
        "errors": errors,
        "allow_missing_group": allow_missing_group,
        "mutation_aware_grouping": True,
        "out_dir": str(out),
    }


def chronological_split(
    manifest: str | Path,
    out_dir: str | Path,
    train: float = 0.6,
    validation: float = 0.2,
    allow_missing_date: bool = False,
) -> dict[str, Any]:
    if train < 0 or validation < 0 or train + validation > 1:
        raise ValueError("invalid train/validation fractions")
    manifest_path = Path(manifest).resolve()
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = list(raw.get("cases", []))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    case_map = {str(c.get("id")): c for c in cases}
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for cid in case_map:
        find(cid)
    for cid, case in case_map.items():
        pcase = case.get("mutation_of")
        if pcase and str(pcase) in case_map:
            union(cid, str(pcase))
        counterpart = case.get("counterpart")
        if counterpart and str(counterpart) in case_map:
            union(cid, str(counterpart))
        pair_id = case.get("pair_id") or (case.get("dataset") or {}).get("pair_id")
        if pair_id:
            pass
    pair_groups = {}
    for cid, case in case_map.items():
        pair_id = case.get("pair_id") or (case.get("dataset") or {}).get("pair_id")
        if pair_id:
            pair_groups.setdefault(str(pair_id), []).append(cid)
    for members in pair_groups.values():
        for a, b in zip(members, members[1:]):
            union(a, b)
    components: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        components.setdefault(find(str(case.get("id"))), []).append(case)
    ordered_groups = sorted(
        components.values(),
        key=lambda members: min(_temporal_key(c, allow_missing_date) for c in members),
    )
    n = len(ordered_groups)
    a = int(math.floor(n * train))
    b = int(math.floor(n * (train + validation)))
    group_buckets = {
        "train": ordered_groups[:a],
        "validation": ordered_groups[a:b],
        "test": ordered_groups[b:],
    }
    buckets = {
        name: [case for members in groups for case in members]
        for name, groups in group_buckets.items()
    }
    dates = {
        name: [
            _temporal_key(c, allow_missing_date).isoformat()
            for c in sorted(members, key=lambda x: _temporal_key(x, allow_missing_date))
        ]
        for name, members in buckets.items()
    }
    errors: list[str] = []
    if group_buckets["train"] and group_buckets["validation"]:
        if min(
            _temporal_key(c, allow_missing_date)
            for members in group_buckets["validation"]
            for c in members
        ) < min(
            _temporal_key(c, allow_missing_date)
            for members in group_buckets["train"]
            for c in members
        ):
            errors.append(
                "temporal group order violation: validation starts before train"
            )
    if group_buckets["validation"] and group_buckets["test"]:
        if min(
            _temporal_key(c, allow_missing_date)
            for members in group_buckets["test"]
            for c in members
        ) < min(
            _temporal_key(c, allow_missing_date)
            for members in group_buckets["validation"]
            for c in members
        ):
            errors.append(
                "temporal group order violation: test starts before validation"
            )
    for name, members in buckets.items():
        prepared = _materialize_graphs(members, manifest_path, out)
        payload = _partition_payload(
            raw,
            name,
            "chronological",
            prepared,
            split_dir=out,
            source_manifest_parent=manifest_path.parent,
            source_manifest=manifest_path,
        )
        (out / f"{name}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return {
        "status": "PASS" if not errors else "FAIL",
        "strategy": "chronological",
        "counts": {k: len(v) for k, v in buckets.items()},
        "group_count": n,
        "mutation_aware_grouping": True,
        "date_ranges": {
            k: ({"min": v[0], "max": v[-1]} if v else None) for k, v in dates.items()
        },
        "errors": errors,
        "allow_missing_date": allow_missing_date,
        "out_dir": str(out),
    }


def _lineage_root(case: dict[str, Any], case_map: dict[str, dict[str, Any]]) -> str:
    cur = str(case.get("id", ""))
    seen: set[str] = set()
    while cur in case_map and case_map[cur].get("mutation_of"):
        if cur in seen:
            return f"__cycle__:{cur}"
        seen.add(cur)
        cur = str(case_map[cur].get("mutation_of"))
    return cur


def audit_split_directory(
    directory: str | Path, *, strategy: str | None = None
) -> dict[str, Any]:
    """Audit train/validation/test manifests for leakage across partitions.

    Checks case IDs, grouping keys, mutation ancestry, graph digests and available
    normalized-source hashes. It never invents missing grouping metadata.
    """
    root = Path(directory).resolve()
    names = ["train", "validation", "test"]
    manifests = {}
    errors: list[str] = []
    warnings: list[str] = []
    for name in names:
        p = root / f"{name}.json"
        if p.is_file():
            manifests[name] = json.loads(p.read_text(encoding="utf-8"))
    if len(manifests) < 2:
        return {
            "status": "FAIL",
            "errors": [
                "split directory must contain at least two of train.json, validation.json, test.json"
            ],
            "warnings": [],
        }

    all_cases = []
    case_owner: dict[str, str] = {}
    graph_owner: dict[str, str] = {}
    source_owner: dict[str, str] = {}
    group_owner: dict[str, str] = {}
    lineage_map: dict[str, dict[str, Any]] = {}
    for part, raw in manifests.items():
        for c in raw.get("cases", []):
            if not isinstance(c, dict):
                errors.append(f"{part}: non-object case")
                continue
            cid = str(c.get("id", ""))
            if not cid:
                errors.append(f"{part}: case missing id")
                continue
            lineage_map[cid] = c
            if cid in case_owner and case_owner[cid] != part:
                errors.append(f"case leakage: {cid} in {case_owner[cid]} and {part}")
            case_owner[cid] = part
            all_cases.append((part, c))
            gd = c.get("canonical_graph_digest") or c.get("graph_sha256")
            if not c.get("canonical_graph_digest") and c.get("graph"):
                try:
                    from .parsers import parse_graph
                    from .evaluator import _safe_case_path

                    gp = _safe_case_path(root / f"{part}.json", str(c["graph"]))
                    if gp.is_file():
                        gd = parse_graph(gp).digest()
                except Exception as exc:
                    warnings.append(
                        f"{part}/{cid}: graph digest unavailable for leakage audit: {exc}"
                    )
            if gd:
                gd = str(gd)
                if gd in graph_owner and graph_owner[gd] != part:
                    errors.append(
                        f"graph leakage across partitions: {gd} in {graph_owner[gd]} and {part}"
                    )
                graph_owner[gd] = part
            sh = c.get("normalized_source_hash") or (
                c.get("source_metadata") or {}
            ).get("normalized_source_hash")
            if sh:
                sh = str(sh)
                if sh in source_owner and source_owner[sh] != part:
                    errors.append(
                        f"normalized-source leakage across partitions: {sh} in {source_owner[sh]} and {part}"
                    )
                source_owner[sh] = part

    if strategy:
        for part, raw in manifests.items():
            for c in raw.get("cases", []):
                try:
                    group = _required_group(c, strategy, allow_missing=False)
                except Exception as exc:
                    errors.append(f"{part}/{c.get('id')}: {exc}")
                    continue
                if group in group_owner and group_owner[group] != part:
                    errors.append(
                        f"group leakage under {strategy}: {group} in {group_owner[group]} and {part}"
                    )
                group_owner[group] = part

    pair_owner = {}
    for part, c in all_cases:
        pair_id = c.get("pair_id") or (c.get("dataset") or {}).get("pair_id")
        if pair_id:
            pair_id = str(pair_id)
            if pair_id in pair_owner and pair_owner[pair_id] != part:
                errors.append(
                    f"pair leakage across partitions: {pair_id} in {pair_owner[pair_id]} and {part}"
                )
            pair_owner[pair_id] = part
        counterpart = c.get("counterpart")
        if counterpart:
            owner = case_owner.get(str(counterpart))
            if owner and owner != part:
                errors.append(
                    f"counterpart leakage across partitions: {c.get('id')} ({part}) -> {counterpart} ({owner})"
                )
        parent = c.get("mutation_of")
        if parent:
            owner = case_owner.get(str(parent))
            if owner and owner != part:
                errors.append(
                    f"mutation lineage crosses partitions: {c.get('id')} ({part}) -> {parent} ({owner})"
                )

    for cid, c in lineage_map.items():
        root_case = _lineage_root(c, lineage_map)
        part = case_owner.get(cid)
        root_part = case_owner.get(root_case)
        if part and root_part and part != root_part:
            errors.append(
                f"mutation ancestry split across partitions: {cid} -> lineage root {root_case}"
            )

    chronological = any(
        str((raw.get("split") or {}).get("strategy")) == "chronological"
        for raw in manifests.values()
    )
    if chronological:
        ranges = {}
        for part, raw in manifests.items():
            vals = []
            for c in raw.get("cases", []):
                try:
                    vals.append(_temporal_key(c, False))
                except Exception as exc:
                    errors.append(f"{part}/{c.get('id')}: {exc}")
            if vals:
                ranges[part] = (min(vals), max(vals))
        order = ["train", "validation", "test"]
        for a, b in zip(order, order[1:]):
            if a in ranges and b in ranges and ranges[a][1] > ranges[b][0]:
                errors.append(f"chronological overlap/order violation: {a} and {b}")

    valid_group_strategies = {"repository", "project", "cve"}
    group_strategy = strategy if strategy in valid_group_strategies else None

    if group_strategy is None:
        declared_strategies = {
            str((raw.get("split") or {}).get("strategy"))
            for raw in manifests.values()
            if (raw.get("split") or {}).get("strategy")
        }
        if len(declared_strategies) == 1:
            declared = next(iter(declared_strategies))
            if declared in valid_group_strategies:
                group_strategy = declared

    partition_summary = {}
    quality_warnings = []

    for part, raw in manifests.items():
        part_cases = [c for c in raw.get("cases", []) if isinstance(c, dict)]
        label_counts = {}
        identified_groups = set()
        cases_without_group_identity = 0
        source_hash_counts = {}
        source_hash_coverage = 0

        for case in part_cases:
            label = str(case.get("expected", "UNKNOWN")).upper()
            label_counts[label] = label_counts.get(label, 0) + 1

            if group_strategy:
                try:
                    group_id = _required_group(
                        case, group_strategy, allow_missing=False
                    )
                    identified_groups.add(group_id)
                except Exception:
                    cases_without_group_identity += 1

            source_metadata = case.get("source_metadata")
            if not isinstance(source_metadata, dict):
                source_metadata = {}

            source_hash = case.get("normalized_source_hash") or source_metadata.get(
                "normalized_source_hash"
            )
            if source_hash:
                source_hash_coverage += 1
                source_hash = str(source_hash)
                source_hash_counts[source_hash] = (
                    source_hash_counts.get(source_hash, 0) + 1
                )

        partition_summary[part] = {
            "case_count": len(part_cases),
            "label_counts": dict(sorted(label_counts.items())),
            "identified_groups": (len(identified_groups) if group_strategy else None),
            "cases_without_group_identity": (
                cases_without_group_identity if group_strategy else None
            ),
            "source_hash_coverage": source_hash_coverage,
            "unique_source_hashes": len(source_hash_counts),
            "duplicate_source_hash_groups": sum(
                1 for count in source_hash_counts.values() if count > 1
            ),
        }

        if (
            group_strategy
            and part in {"validation", "test"}
            and part_cases
            and len(identified_groups) < 2
        ):
            quality_warnings.append(
                f"{part} partition has fewer than two identified "
                f"{group_strategy} groups; cluster-aware evaluation "
                "is not estimable for this partition"
            )

    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "partition_summary": partition_summary,
        "quality_warnings": quality_warnings,
        "partitions": {k: len(v.get("cases", [])) for k, v in manifests.items()},
        "case_count": len(all_cases),
        "unique_case_ids": len(case_owner),
        "unique_graph_hashes": len(graph_owner),
        "unique_source_hashes": len(source_owner),
        "groups": len(group_owner),
        "strategy": strategy,
    }
