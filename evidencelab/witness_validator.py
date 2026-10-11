from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from . import SCHEMA_VERSION
from .errors import EvidenceLabError
from .models import Graph
from .spec import Pattern
from .provenance import sha256_json


class WitnessValidationError(EvidenceLabError):
    pass


def _validate_match_structure(
    graph: Graph, pattern: Pattern, match: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if match.get("pattern_id") != pattern.pattern_id:
        errors.append("pattern_id mismatch")
    evidence_trace = match.get("evidence_trace", {}) or {}
    if (
        evidence_trace.get("graph_digest")
        and evidence_trace["graph_digest"] != graph.digest()
    ):
        errors.append("graph_digest mismatch")
    if evidence_trace.get("pattern_digest"):
        # The matcher records a canonical pattern digest; independent validation does not
        # trust the trace alone, but it can still require its presence.
        pass
    if evidence_trace.get("candidate_truncated") or evidence_trace.get(
        "analysis_truncated"
    ):
        errors.append(
            "analysis search was truncated; witness cannot be independently accepted as definitive"
        )

    witnesses = match.get("witnesses", [])
    if not isinstance(witnesses, list):
        errors.append("witnesses must be a list")
        witnesses = []
    required_pattern_witnesses = {w.id for w in pattern.witnesses if w.required}
    returned_ids = {str(w.get("witness_id")) for w in witnesses}
    missing = sorted(required_pattern_witnesses - returned_ids)
    if missing:
        errors.append(
            "required witnesses absent from match result: " + ", ".join(missing)
        )

    for witness in witnesses:
        wid = str(witness.get("witness_id", ""))
        status = str(witness.get("status", "UNKNOWN"))
        bindings = witness.get("bindings", {}) or {}
        if status == "MATCH" and not bindings:
            errors.append(f"{wid}: MATCH witness has no bindings")
        claims = witness.get("claims", []) or []
        for claim in claims:
            if claim.get("required", False) and str(claim.get("status")) != "PROVEN":
                errors.append(
                    f"{wid}: required claim {claim.get('claim_id')} is not PROVEN"
                )
        counters = witness.get("counter_evidence", []) or []
        if status == "MATCH" and pattern.counter_claims:
            if not counters:
                errors.append(
                    f"{wid}: MATCH witness has no counter-evidence evaluation"
                )
            for counter in counters:
                if (
                    str(counter.get("status")) == "UNKNOWN"
                    and pattern.counter_unknown_policy == "block_match"
                ):
                    errors.append(
                        f"{wid}: unknown counter-evidence blocks a definitive MATCH"
                    )
        if status == "MATCH" and witness.get("search_complete") is False:
            # A proof-of-existence witness does not require exhaustive candidate enumeration.
            # Search completeness is recorded as a separate quality/performance dimension.
            warnings.append(
                f"{wid}: candidate search stopped after a valid witness; witness validity is checked by fixed-binding replay"
            )
    if pattern.provenance and not evidence_trace.get("pattern_digest"):
        warnings.append(
            "pattern provenance exists but match trace does not carry a pattern digest"
        )
    payload_digest = sha256_json({"graph_digest": graph.digest(), "match": match})
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "graph_digest": graph.digest(),
        "witness_digest": payload_digest,
        "witness_count": len(witnesses),
    }


def validate_match_result(
    graph: Graph, pattern: Pattern, match: dict[str, Any]
) -> dict[str, Any]:
    """Independently validate the structural integrity of one witness result.

    This is intentionally not a second program analyzer. It checks consistency, bindings,
    proof-state requirements, truncation safety and counter-evidence policy independently
    from the evaluator's report assembly.
    """
    return _validate_match_structure(graph, pattern, match)


def validate_benchmark_matches(
    benchmark: str | Path,
    pattern: Pattern,
    *,
    max_cases: int | None = None,
    only_status: str | None = "MATCH",
) -> dict[str, Any]:
    """Independently replay the concrete witness produced by the matcher.

    The normal Matcher is allowed to search for candidate bindings. The validator does
    not search. It runs the matcher once to obtain the report and then passes each report
    to :class:`WitnessReplay`, which checks only the fixed bindings/claims that were
    emitted. This catches stale graph digests, fabricated bindings, broken relations,
    incorrect comparisons, missing counter-evidence and proof-state mismatches.
    """
    from .evaluator import _safe_case_path
    from .parsers import parse_graph
    from .matcher import Matcher

    path = Path(benchmark).resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    selected = []
    for case in raw.get("cases", []):
        if only_status and str(case.get("expected", "")).upper() != only_status.upper():
            continue
        selected.append(case)
    if max_cases is not None:
        selected = selected[:max_cases]
    if not selected:
        return {
            "status": "FAIL",
            "validated_cases": 0,
            "selected_cases": 0,
            "only_expected": only_status,
            "errors": [
                "no benchmark cases selected for independent witness validation"
            ],
            "truncated_error_list": False,
            "validation_mode": "fixed-binding-semantic-replay",
        }
    errors = []
    validated = 0
    passed_cases = 0
    for case in selected:
        cid = str(case.get("id"))
        try:
            graph = parse_graph(_safe_case_path(path, str(case["graph"])))
            match = Matcher(graph).run(pattern).to_dict()
            structure = _validate_match_structure(graph, pattern, match)
            expected = str(case.get("expected", "UNKNOWN")).upper()
            actual = str(match.get("status", "UNKNOWN")).upper()
            acceptable = (
                (expected == "MATCH" and actual == "MATCH")
                or (expected == "NO_MATCH" and actual == "NO_MATCH")
                or (expected == "UNKNOWN" and actual in {"UNKNOWN", "PARTIAL"})
            )
            if not acceptable:
                errors.append(
                    {
                        "id": cid,
                        "status": "FAIL",
                        "errors": [
                            f"expected {expected} but matcher produced {actual}"
                        ],
                        "validation_mode": "fixed-binding-semantic-replay",
                    }
                )
                validated += 1
                continue
            replay = (
                __import__("evidencelab.witness_replay", fromlist=["WitnessReplay"])
                .WitnessReplay(graph, pattern)
                .validate(match)
            )
            combined = {
                "status": "PASS"
                if structure["status"] == "PASS" and replay["status"] == "PASS"
                else "FAIL",
                "structural": structure,
                "semantic_replay": replay,
                "validation_mode": "fixed-binding-semantic-replay",
            }
            if combined["status"] != "PASS":
                errors.append({"id": cid, **combined})
            else:
                passed_cases += 1
            validated += 1
        except Exception as exc:
            errors.append({"id": cid, "status": "FAIL", "errors": [str(exc)]})
    return {
        "status": "PASS" if not errors else "FAIL",
        "validated_cases": validated,
        "passed_cases": passed_cases,
        "failed_cases": len(errors),
        "selected_cases": len(selected),
        "only_expected": only_status,
        "errors": errors[:100],
        "truncated_error_list": len(errors) > 100,
        "validation_mode": "fixed-binding-semantic-replay",
    }


def validate_report(report_path: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
    graph_data = raw.get("graph")
    if not isinstance(graph_data, dict):
        raise WitnessValidationError("report has no canonical graph summary")
    errors = []
    match = raw.get("match", {})
    if not match:
        errors.append("report has no match result")
    if (
        raw.get("graph_digest")
        and match.get("evidence_trace", {}).get("graph_digest")
        and raw["graph_digest"] != match["evidence_trace"]["graph_digest"]
    ):
        errors.append("report graph_digest disagrees with match evidence_trace")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def replay_stored_report(
    report: dict[str, Any], graph_path: str | Path, pattern: Pattern
) -> dict[str, Any]:
    """Replay a previously stored matcher result without invoking candidate search.

    This is the strongest EvidenceLab replay mode: the validator consumes only the
    concrete witness emitted by an earlier evaluation run and checks its bindings and
    claim states against the referenced graph and pattern.
    """
    from .parsers import parse_graph
    from .witness_replay import WitnessReplay

    graph = parse_graph(Path(graph_path))
    errors: list[str] = []
    if str(report.get("schema_version")) != SCHEMA_VERSION:
        errors.append("unsupported stored report schema_version")
    matcher = report.get("matcher") or report.get("match")
    if not isinstance(matcher, dict):
        errors.append("stored report has no matcher/match object")
        return {
            "status": "FAIL",
            "errors": errors,
            "validation_mode": "stored-fixed-binding-replay",
        }
    expected_graph = report.get("graph_digest")
    if expected_graph and str(expected_graph) != graph.digest():
        errors.append("stored report graph_digest mismatch")
    from .provenance import sha256_file

    pattern_path = report.get("pattern")
    stored_pattern_sha = report.get("pattern_sha256")
    if stored_pattern_sha:
        if (
            pattern_path
            and Path(str(pattern_path)).is_file()
            and sha256_file(Path(str(pattern_path))) != str(stored_pattern_sha)
        ):
            errors.append("stored report pattern_sha256 mismatch")
        if (
            getattr(pattern, "source_path", None)
            and Path(str(pattern.source_path)).is_file()
            and sha256_file(Path(str(pattern.source_path))) != str(stored_pattern_sha)
        ):
            errors.append("supplied pattern_sha256 mismatch")
    replay = WitnessReplay(graph, pattern).validate(matcher)
    errors.extend(str(x) for x in replay.get("errors", []))
    if (
        str(report.get("actual", matcher.get("status"))).upper()
        != str(matcher.get("status", "UNKNOWN")).upper()
    ):
        errors.append("stored report actual status disagrees with matcher status")
    if errors:
        return {
            "status": "FAIL",
            "errors": errors,
            "replay": replay,
            "validation_mode": "stored-fixed-binding-replay",
        }
    return {
        "status": "PASS",
        "errors": [],
        "replay": replay,
        "validation_mode": "stored-fixed-binding-replay",
    }
