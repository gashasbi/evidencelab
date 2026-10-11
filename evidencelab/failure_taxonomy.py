from __future__ import annotations

from typing import Any

FAILURE_TAXONOMY = {
    "PATTERN": "Evidence definition or matcher contract is invalid.",
    "DATA": "Input graph/source/data is missing, malformed, corrupted, or inconsistent.",
    "ANALYSIS": "Required analysis evidence is unavailable, incomplete, truncated, or ambiguous.",
    "INFRA": "Execution failed because of timeout, memory/resource exhaustion, process failure, or environment failure.",
    "BENCHMARK": "Benchmark design violates corpus size, diversity, split, lineage, dimension, or independence rules.",
    "VALIDATION": "Independent witness, hidden benchmark, replay, or external validation failed.",
    "PROVENANCE": "Evidence/fact/label cannot be traced to authoritative inputs or activities.",
    "LEAKAGE": "Public/evaluation partitions share disallowed content, lineage, identities, or near duplicates.",
    "PERFORMANCE": "Runtime/search/memory cost exceeds the configured evaluation budget.",
}


def categorize_failure(message: str) -> str:
    m = str(message).lower()
    if any(
        x in m
        for x in (
            "pattern",
            "claim",
            "selector",
            "family_id",
            "tri_state",
            "signature-only",
            "evidence_contract",
        )
    ):
        return "PATTERN"
    if any(
        x in m
        for x in (
            "graph file",
            "source file",
            "malformed",
            "invalid expected",
            "duplicate case id",
            "digest has conflicting",
            "missing graph",
        )
    ):
        return "DATA"
    if any(
        x in m
        for x in (
            "analysis",
            "incomplete",
            "truncated",
            "unknown extent",
            "capability",
            "parse health",
        )
    ):
        return "ANALYSIS"
    if any(
        x in m for x in ("timeout", "resource", "oom", "memory", "infra", "process")
    ):
        return "INFRA"
    if any(
        x in m
        for x in (
            "case minimum",
            "corpus",
            "dimension",
            "diversity",
            "cluster",
            "split",
            "mutation",
            "unique graph",
        )
    ):
        return "BENCHMARK"
    if any(
        x in m
        for x in (
            "hidden",
            "witness",
            "replay",
            "external validation",
            "validation required",
        )
    ):
        return "VALIDATION"
    if any(
        x in m
        for x in (
            "provenance",
            "label authority",
            "label provenance",
            "derivation input",
        )
    ):
        return "PROVENANCE"
    if any(
        x in m
        for x in ("leakage", "overlap", "near-duplicate", "duplicate source", "lineage")
    ):
        return "LEAKAGE"
    if any(x in m for x in ("performance", "p95", "p99", "search cost", "over limit")):
        return "PERFORMANCE"
    return "VALIDATION"


def classify_errors(errors: list[str]) -> dict[str, int]:
    out = {k: 0 for k in FAILURE_TAXONOMY}
    for err in errors or []:
        out[categorize_failure(str(err))] += 1
    return {k: v for k, v in out.items() if v}


def taxonomy_payload(errors: list[str] | None = None) -> dict[str, Any]:
    return {"definitions": FAILURE_TAXONOMY, "counts": classify_errors(errors or [])}
