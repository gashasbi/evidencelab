from __future__ import annotations

from collections import defaultdict
from math import sqrt
import random
from typing import Any, Iterable


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _cluster_groups(
    cases: Iterable[dict[str, Any]],
    key_priority=("repository", "project", "dataset", "case_id"),
) -> list[list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for i, case in enumerate(cases):
        ds = case.get("dataset") if isinstance(case.get("dataset"), dict) else {}
        key = None
        for k in key_priority:
            raw = case.get(k) if k in case else ds.get(k)
            if raw:
                key = str(raw)
                break
        if key is None:
            key = f"__case_{i}"
        groups[key].append(case)
    return list(groups.values())


def cluster_bootstrap_mean(
    values_by_case: list[tuple[str, float]], *, rounds: int = 2000, seed: int = 7
) -> dict[str, Any]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for cluster, value in values_by_case:
        grouped[cluster].append(float(value))
    clusters = list(grouped.values())
    if not clusters:
        return {"mean": None, "ci95": [None, None], "clusters": 0, "rounds": 0}
    rng = random.Random(seed)
    point = _mean([_mean(c) for c in clusters])
    samples = []
    for _ in range(max(100, rounds)):
        picked = [clusters[rng.randrange(len(clusters))] for _ in clusters]
        samples.append(_mean([_mean(c) for c in picked]))
    samples.sort()
    lo = samples[int(0.025 * (len(samples) - 1))]
    hi = samples[int(0.975 * (len(samples) - 1))]
    return {
        "mean": point,
        "ci95": [lo, hi],
        "clusters": len(clusters),
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
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
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
        "case_id",
    ),
) -> dict[str, Any]:
    """Cluster-bootstrap binary classification metrics.

    A cluster is resampled as a unit. Pair identifiers take precedence over repository
    identity so vulnerable/fixed counterparts do not masquerade as independent samples.
    The returned confidence intervals are percentile intervals over cluster resamples.
    """
    rows = list(results)
    groups: dict[str, list[Any]] = defaultdict(list)
    for i, result in enumerate(rows):
        detail = getattr(result, "detail", {}) or {}
        dataset = (
            detail.get("dataset") if isinstance(detail.get("dataset"), dict) else {}
        )
        cid = str(getattr(result, "case_id", i))
        if isinstance(result, dict):
            dataset = result.get("dataset") or {}
            cid = str(result.get("case_id") or result.get("id") or i)
        key = None
        if isinstance(result, dict):
            for k in cluster_priority:
                raw = result.get(k) if k in result else dataset.get(k)
                if raw:
                    key = str(raw)
                    break
        if key is None:
            key = str(getattr(result, "cluster_key", "")) or f"__case_{cid}"
        groups[key].append(result)
    if not groups:
        return {"status": "EMPTY", "clusters": 0, "rounds": 0, "point": {}, "ci95": {}}

    def counts(items: list[Any]) -> tuple[int, int, int, int]:
        tp = fp = tn = fn = 0
        for r in items:
            expected = (
                str(r.get("expected", "")).upper()
                if isinstance(r, dict)
                else str(getattr(r, "expected", "")).upper()
            )
            actual = (
                str(r.get("actual", "")).upper()
                if isinstance(r, dict)
                else str(getattr(r, "actual", "")).upper()
            )
            if expected == "MATCH":
                tp += int(actual == "MATCH")
                fn += int(actual != "MATCH")
            elif expected == "NO_MATCH":
                fp += int(actual == "MATCH")
                tn += int(actual == "NO_MATCH")
        return tp, fp, tn, fn

    flat = [r for rs in groups.values() for r in rs]
    point = _metric_from_counts(*counts(flat))
    rng = random.Random(seed)
    cluster_lists = list(groups.values())
    series = {k: [] for k in point}
    for _ in range(max(100, rounds)):
        picked = [
            cluster_lists[rng.randrange(len(cluster_lists))] for _ in cluster_lists
        ]
        sampled = [r for c in picked for r in c]
        m = _metric_from_counts(*counts(sampled))
        for k, v in m.items():
            if v is not None:
                series[k].append(v)
    ci = {}
    for k, vals in series.items():
        vals.sort()
        if not vals:
            ci[k] = [None, None]
        else:
            ci[k] = [
                vals[int(0.025 * (len(vals) - 1))],
                vals[int(0.975 * (len(vals) - 1))],
            ]
    return {
        "status": "PASS",
        "clusters": len(cluster_lists),
        "rounds": max(100, rounds),
        "unit": "cluster",
        "cluster_priority": list(cluster_priority),
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
