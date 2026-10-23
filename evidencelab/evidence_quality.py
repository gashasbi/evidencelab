from __future__ import annotations
from typing import Any
from .spec import Pattern


def _witness_quality(detail: dict[str, Any], pattern: Pattern) -> dict[str, Any]:
    witnesses = detail.get("witnesses", []) if isinstance(detail, dict) else []
    if not isinstance(witnesses, list) or not witnesses:
        return {
            "witnesses": 0,
            "complete": 0,
            "coherent": 0,
            "counter": 0,
            "provenance": 0,
            "localized": 0,
            "minimal": 0,
            "relevant": 0,
            "search_complete": 0,
        }
    total = len(witnesses)
    complete = coherent = counter = provenance = localized = minimal = relevant = (
        search_complete
    ) = 0
    required = [c.id for c in pattern.claims if c.required]
    max_hops = int((pattern.path_budget or {}).get("max_hops", 24) or 24)
    for w in witnesses:
        bindings = w.get("bindings", {}) or {}
        claims = w.get("claims", []) or []
        statuses = {
            str(c.get("claim_id")): str(c.get("status", "UNKNOWN")) for c in claims
        }
        ok_claims = all(statuses.get(cid) == "PROVEN" for cid in required)
        complete += int(bool(bindings) and ok_claims)
        coherent += int(
            bool(bindings)
            and ok_claims
            and len(set(bindings.values())) == len(bindings.values())
        )
        counter += int(
            (not pattern.counter_claims) or bool(w.get("counter_evidence", []))
        )
        trace = detail.get("evidence_trace", {}) or {}
        ledger = detail.get("ledger", {}) or {}
        ledger_items = ledger.get("items", []) if isinstance(ledger, dict) else []
        provenance += int(
            bool(trace.get("pattern_digest"))
            and bool(trace.get("graph_digest"))
            and all(
                (
                    x.get("provenance")
                    for x in ledger_items
                    if x.get("kind") in {"FACT", "COUNTER"}
                    and x.get("state") in {"PROVEN", "DISPROVEN"}
                )
            )
        )
        localized += int(any((c.get("matches") or c.get("locations")) for c in claims))

        claim_count = len(claims)
        minimal += int(
            ok_claims and claim_count <= max(len(required), len(required) + 2)
        )

        lengths = []
        for c in claims:
            for m in c.get("matches", []) or []:
                for path in m.get("path", []) if isinstance(m, dict) else []:
                    lengths.append(max(0, len(path) - 1))
        relevant += int(
            bool(bindings)
            and all(x <= max_hops for x in lengths)
            and any((c.get("matches") or []) for c in claims)
        )
        search_complete += int(w.get("search_complete", False) is True)
    return {
        "witnesses": total,
        "complete": complete,
        "coherent": coherent,
        "counter": counter,
        "provenance": provenance,
        "localized": localized,
        "minimal": minimal,
        "relevant": relevant,
        "search_complete": search_complete,
    }


def compute_evidence_quality(results: list[Any], pattern: Pattern) -> dict[str, Any]:
    matched = 0
    complete = coherent = counter = provenance = localized = minimal = relevant = (
        replay_pass
    ) = replay_evaluated = search_complete = 0
    for r in results:
        actual = getattr(r, "actual", None)
        detail = getattr(r, "detail", {}) or {}
        if actual != "MATCH":
            continue
        matched += 1
        q = _witness_quality(detail, pattern)
        complete += int(q["complete"] > 0)
        coherent += int(q["coherent"] > 0)
        counter += int(q["counter"] > 0)
        provenance += int(q["provenance"] > 0)
        localized += int(q["localized"] > 0)
        minimal += int(q["minimal"] > 0)
        relevant += int(q["relevant"] > 0)
        search_complete += int(q["search_complete"] > 0)
        replay = detail.get("witness_replay") or detail.get(
            "independent_witness_validation"
        )
        if isinstance(replay, dict) and replay.get("status") in {"PASS", "FAIL"}:
            replay_evaluated += 1
            replay_pass += int(replay.get("status") == "PASS")
    denom = matched or 0
    return {
        "matched_cases": matched,
        "witness_completeness_rate": complete / denom if denom else None,
        "witness_coherence_rate": coherent / denom if denom else None,
        "counter_evidence_evaluation_rate": counter / denom if denom else None,
        "provenance_trace_rate": provenance / denom if denom else None,
        "localization_rate": localized / denom if denom else None,
        "minimality_rate": minimal / denom if denom else None,
        "relevance_rate": relevant / denom if denom else None,
        "independent_replay_rate": (
            replay_pass / replay_evaluated if replay_evaluated else None
        ),
        "independent_replay_evaluated_cases": replay_evaluated,
        "witness_search_complete_rate": search_complete / denom if denom else None,
    }
