from __future__ import annotations

from collections import defaultdict
from math import sqrt
import random
from typing import Any, Iterable


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _cluster_groups(
    cases: Iterable[dict[str, Any]],
    key_priority=("repository", "project", "dataset"),
) -> list[list[dict[str, Any]]]:
    """Group only cases with an evidence-backed cluster identity.

    A case ID is not evidence of statistical independence. Cases whose
    repository/project/dataset identity is unavailable are not assigned
    synthetic singleton clusters.
    """
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case in cases:
        ds = case.get("dataset") if isinstance(case.get("dataset"), dict) else {}
        key = None

        for name in key_priority:
            if name in {"id", "case_id"}:
                continue

            if name == "dataset":
                raw = case.get("dataset_name") or ds.get("name")
                if not raw and isinstance(case.get("dataset"), str):
                    raw = case.get("dataset")
            else:
                raw = case.get(name) or ds.get(name)

            if raw is not None and str(raw).strip():
                key = f"{name}:{str(raw).strip()}"
                break

        if key is not None:
            groups[key].append(case)

    return list(groups.values())


def cluster_bootstrap_mean(
    values_by_case: list[tuple[str | None, float]],
    *,
    rounds: int = 2000,
    seed: int = 7,
) -> dict[str, Any]:
    """Estimate a mean and cluster-bootstrap CI only with identified clusters.

    If any observation lacks an identifiable cluster, or fewer than two
    clusters are available, report the interval as unavailable instead of
    treating case IDs as independent clusters.
    """
    grouped: dict[str, list[float]] = defaultdict(list)
    unclustered = 0

    for cluster, value in values_by_case:
        key = str(cluster).strip() if cluster is not None else ""
        if not key:
            unclustered += 1
            continue
        grouped[key].append(float(value))

    clusters = list(grouped.values())
    unavailable_ci = [None, None]

    if unclustered:
        return {
            "status": "UNAVAILABLE_MISSING_CLUSTER_ID",
            "mean": None,
            "ci95": unavailable_ci,
            "clusters": len(clusters),
            "unclustered_cases": unclustered,
            "rounds": 0,
        }

    if not clusters:
        return {
            "status": "EMPTY",
            "mean": None,
            "ci95": unavailable_ci,
            "clusters": 0,
            "unclustered_cases": 0,
            "rounds": 0,
        }

    if len(clusters) < 2:
        return {
            "status": "UNAVAILABLE_INSUFFICIENT_CLUSTERS",
            "mean": None,
            "ci95": unavailable_ci,
            "clusters": len(clusters),
            "unclustered_cases": 0,
            "rounds": 0,
        }

    rng = random.Random(seed)
    point = _mean([_mean(cluster) for cluster in clusters])
    samples = []

    for _ in range(max(100, rounds)):
        picked = [clusters[rng.randrange(len(clusters))] for _ in clusters]
        samples.append(_mean([_mean(cluster) for cluster in picked]))

    samples.sort()
    lo = samples[int(0.025 * (len(samples) - 1))]
    hi = samples[int(0.975 * (len(samples) - 1))]

    return {
        "status": "PASS",
        "mean": point,
        "ci95": [lo, hi],
        "clusters": len(clusters),
        "unclustered_cases": 0,
        "rounds": len(samples),
    }


def paired_delta(before: list[float], after: list[float]) -> dict[str, Any]:
    n = min(len(before), len(after))
    if n == 0:
        return {"n": 0, "mean_delta": None, "sd_delta": None, "stderr": None}
    deltas = [float(after[i]) - float(before[i]) for i in range(n)]
    mean = _mean(deltas)
    if n > 1:
        variance = sum((x - mean) ** 2 for x in deltas) / (n - 1)
        sd = sqrt(variance)
        stderr = sd / sqrt(n)
    else:
        sd = 0.0
        stderr = 0.0
    return {"n": n, "mean_delta": mean, "sd_delta": sd, "stderr": stderr}


def _metric_from_counts(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | None]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    fpr = fp / (fp + tn) if fp + tn else None
    fnr = fn / (tp + fn) if tp + fn else None
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


def cluster_bootstrap_binary_metrics(
    results: Iterable[Any],
    *,
    rounds: int = 2000,
    seed: int = 7,
    cluster_priority: tuple[str, ...] = (
        "pair_id",
        "repository",
        "project",
        "dataset",
    ),
) -> dict[str, Any]:
    """Cluster-bootstrap classification metrics using identified clusters only.

    Pair, repository, project, or dataset metadata can identify a cluster.
    Case IDs cannot: missing cluster identities and fewer than two clusters
    make cluster-based confidence intervals unavailable.
    """
    rows = list(results)
    effective_priority = tuple(
        key for key in cluster_priority if key not in {"case_id", "id"}
    )

    if not rows:
        return {
            "status": "EMPTY",
            "clusters": 0,
            "unclustered_cases": 0,
            "rounds": 0,
            "point": {},
            "ci95": {},
            "cluster_priority": list(effective_priority),
        }

    groups: dict[str, list[Any]] = defaultdict(list)
    unclustered = []

    for result in rows:
        detail = getattr(result, "detail", {}) or {}
        detail_dataset = (
            detail.get("dataset") if isinstance(detail, dict) else {}
        )
        dataset = (
            detail_dataset if isinstance(detail_dataset, dict) else {}
        )

        if isinstance(result, dict):
            candidate = result.get("dataset")
            if isinstance(candidate, dict):
                dataset = candidate

        key = None

        for name in effective_priority:
            if name == "dataset":
                if isinstance(result, dict):
                    raw = result.get("dataset_name")
                    candidate = result.get("dataset")
                    if not raw and isinstance(candidate, dict):
                        raw = candidate.get("name")
                    elif not raw and isinstance(candidate, str):
                        raw = candidate
                    if not raw:
                        raw = dataset.get("name")
                else:
                    raw = getattr(result, "dataset_name", None)
                    if not raw:
                        raw = dataset.get("name")
                    if not raw and isinstance(detail, dict):
                        candidate = detail.get("dataset")
                        if isinstance(candidate, str):
                            raw = candidate
            elif isinstance(result, dict):
                raw = result.get(name) or dataset.get(name)
            else:
                raw = getattr(result, name, None)
                if not raw and isinstance(detail, dict):
                    raw = detail.get(name)
                if not raw:
                    raw = dataset.get(name)

            if (
                raw is not None
                and not isinstance(raw, (dict, list, tuple, set))
                and str(raw).strip()
            ):
                key = f"{name}:{str(raw).strip()}"
                break

        if key is None:
            explicit = (
                result.get("cluster_key")
                if isinstance(result, dict)
                else getattr(result, "cluster_key", None)
            )
            if explicit is not None and str(explicit).strip():
                key = f"cluster_key:{str(explicit).strip()}"

        if key is None:
            unclustered.append(result)
        else:
            groups[key].append(result)

    def counts(items: list[Any]) -> tuple[int, int, int, int]:
        tp = fp = tn = fn = 0

        for item in items:
            expected = (
                str(item.get("expected", "")).upper()
                if isinstance(item, dict)
                else str(getattr(item, "expected", "")).upper()
            )
            actual = (
                str(item.get("actual", "")).upper()
                if isinstance(item, dict)
                else str(getattr(item, "actual", "")).upper()
            )

            if expected == "MATCH":
                tp += int(actual == "MATCH")
                fn += int(actual != "MATCH")
            elif expected == "NO_MATCH":
                fp += int(actual == "MATCH")
                tn += int(actual == "NO_MATCH")

        return tp, fp, tn, fn

    point = _metric_from_counts(*counts(rows))
    cluster_lists = list(groups.values())
    unavailable_ci = {key: [None, None] for key in point}

    if unclustered:
        return {
            "status": "UNAVAILABLE_MISSING_CLUSTER_ID",
            "clusters": len(cluster_lists),
            "unclustered_cases": len(unclustered),
            "rounds": 0,
            "unit": "cluster",
            "cluster_priority": list(effective_priority),
            "point": point,
            "ci95": unavailable_ci,
        }

    if len(cluster_lists) < 2:
        return {
            "status": "UNAVAILABLE_INSUFFICIENT_CLUSTERS",
            "clusters": len(cluster_lists),
            "unclustered_cases": 0,
            "rounds": 0,
            "unit": "cluster",
            "cluster_priority": list(effective_priority),
            "point": point,
            "ci95": unavailable_ci,
        }

    rng = random.Random(seed)
    series = {key: [] for key in point}

    for _ in range(max(100, rounds)):
        picked = [
            cluster_lists[rng.randrange(len(cluster_lists))]
            for _ in cluster_lists
        ]
        sampled = [item for cluster in picked for item in cluster]
        metrics = _metric_from_counts(*counts(sampled))

        for key, value in metrics.items():
            if value is not None:
                series[key].append(value)

    ci = {}
    for key, values in series.items():
        values.sort()
        if not values:
            ci[key] = [None, None]
        else:
            ci[key] = [
                values[int(0.025 * (len(values) - 1))],
                values[int(0.975 * (len(values) - 1))],
            ]

    return {
        "status": "PASS",
        "clusters": len(cluster_lists),
        "unclustered_cases": 0,
        "rounds": max(100, rounds),
        "unit": "cluster",
        "cluster_priority": list(effective_priority),
        "point": point,
        "ci95": ci,
    }


def paired_delta_by_id(
    before: dict[str, float], after: dict[str, float]
) -> dict[str, Any]:
    """Compute paired changes by stable case id, never by list position."""
    ids = sorted(set(before) & set(after))
    deltas = [float(after[i]) - float(before[i]) for i in ids]
    mean = _mean(deltas) if deltas else None
    if len(deltas) > 1:
        variance = sum((x - mean) ** 2 for x in deltas) / (len(deltas) - 1)
        sd = sqrt(variance)
        stderr = sd / sqrt(len(deltas))
    else:
        sd = 0.0 if deltas else None
        stderr = 0.0 if deltas else None
    return {
        "n": len(deltas),
        "ids": ids,
        "mean_delta": mean,
        "sd_delta": sd,
        "stderr": stderr,
    }
