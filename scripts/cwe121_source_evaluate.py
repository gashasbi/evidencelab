#!/usr/bin/env python3
"""Evaluate live Joern capture outputs against the CWE-121 reference families.

The source-case expectations are falsifiable hypotheses. This tool never converts an
incomplete graph into a definitive negative and writes a reviewable JSON report.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any


def decision_is_complete(status: str, trace: dict[str, Any]) -> bool:
    """Return whether the trace supports a definitive comparison with an expectation."""
    if trace.get("analysis_incomplete") is not False:
        return False
    if trace.get("witness_search_complete") is not True:
        return False
    if status == "NO_MATCH" and trace.get("graph_complete_for_absence") is not True:
        return False
    return True


def classify_evaluation(
    expected: str | None, actual: str, trace: dict[str, Any]
) -> str:
    if expected is None:
        return "OBSERVED_ONLY"
    if not decision_is_complete(actual, trace):
        return "INCONCLUSIVE"
    return "PASS" if actual == expected else "MISMATCH"


def capture_coverage_errors(
    manifest_cases: list[dict[str, Any]],
    captured_cases: list[dict[str, Any]],
) -> list[str]:
    """Report missing, duplicate, and unexpected source cases."""
    errors: list[str] = []
    expected: dict[str, str] = {}

    for case in manifest_cases:
        source = Path(str(case.get("source", ""))).name
        case_id = str(case.get("id", "<unknown>"))
        if not source:
            errors.append(f"manifest case has no source: {case_id}")
            continue
        if source in expected:
            errors.append(f"duplicate source basename in manifest: {source}")
        else:
            expected[source] = case_id

    counts: dict[str, int] = {}
    for captured in captured_cases:
        source = Path(str(captured.get("source", ""))).name
        if not source:
            errors.append("capture report contains a case with no source")
            continue
        counts[source] = counts.get(source, 0) + 1
        if counts[source] > 1:
            errors.append(f"duplicate source in capture report: {source}")
        if source not in expected:
            errors.append(f"source is absent from source-cases.json: {source}")

    for source in sorted(set(expected) - set(counts)):
        errors.append(f"manifest source is missing from capture report: {source}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "capture_dir", type=Path, help="Output directory from scripts/joern_e2e.sh"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on mismatches or inconclusive expected cases",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    package = root / "examples/cwe-121"
    manifest_path = package / "source-cases.json"
    capture_report_path = args.capture_dir / "e2e-report.json"
    if not manifest_path.is_file() or not capture_report_path.is_file():
        print("ERROR: source-cases.json or e2e-report.json is missing", file=sys.stderr)
        return 2

    from evidencelab.matcher import Matcher
    from evidencelab.parsers import parse_graph
    from evidencelab.spec import Pattern

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    capture_report = json.loads(capture_report_path.read_text(encoding="utf-8"))
    cases_by_source = {
        Path(case["source"]).name: case for case in manifest.get("cases", [])
    }
    patterns = {
        family: Pattern.load(package / relpath)
        for family, relpath in manifest["families"].items()
    }

    results: list[dict[str, Any]] = []
    captured_cases = capture_report.get("cases", [])
    if not isinstance(captured_cases, list):
        print("ERROR: e2e-report.json 'cases' must be a list", file=sys.stderr)
        return 2
    errors = capture_coverage_errors(manifest.get("cases", []), captured_cases)

    for captured in captured_cases:
        source_name = Path(captured.get("source", "")).name
        case = cases_by_source.get(source_name)
        if case is None:
            errors.append(f"source is absent from source-cases.json: {source_name}")
            results.append(
                {
                    "source": source_name,
                    "status": "UNMAPPED_SOURCE",
                }
            )
            continue
        merged = Path(captured.get("merged", ""))
        if (
            captured.get("status") not in {"PASS", "PASS_WITH_WARNING"}
            or not merged.is_file()
        ):
            results.append(
                {
                    "case_id": case["id"],
                    "source": source_name,
                    "status": "CAPTURE_NOT_EVALUATED",
                    "capture_status": captured.get("status"),
                }
            )
            continue

        try:
            graph = parse_graph(merged)
            family_results = []
            for family, pattern in patterns.items():
                result = Matcher(graph).run(pattern)
                actual = result.status
                expected = case.get("expected", {}).get(family)
                trace = result.evidence_trace
                comparison = classify_evaluation(expected, actual, trace)
                family_results.append(
                    {
                        "family": family,
                        "expected": expected,
                        "actual": actual,
                        "comparison": comparison,
                        "decision_complete": decision_is_complete(actual, trace),
                        "analysis_incomplete": trace.get("analysis_incomplete"),
                        "witness_search_complete": trace.get("witness_search_complete"),
                        "graph_complete_for_absence": trace.get(
                            "graph_complete_for_absence"
                        ),
                        "warnings": result.to_dict().get("warnings", []),
                    }
                )
            statuses = {item["comparison"] for item in family_results}
            if "MISMATCH" in statuses:
                case_status = "MISMATCHES_FOUND"
            elif "INCONCLUSIVE" in statuses or "CAPTURE_NOT_EVALUATED" in statuses:
                case_status = "INCONCLUSIVE"
            elif statuses == {"OBSERVED_ONLY"}:
                case_status = "OBSERVED_ONLY"
            elif captured.get("status") == "PASS_WITH_WARNING":
                case_status = "PASS_WITH_WARNING"
            else:
                case_status = "PASS"
            results.append(
                {
                    "case_id": case["id"],
                    "source": source_name,
                    "scope": case.get("scope"),
                    "status": case_status,
                    "families": family_results,
                }
            )
        except Exception as exc:
            errors.append(f"{source_name}: {type(exc).__name__}: {exc}")
            results.append(
                {
                    "case_id": case["id"],
                    "source": source_name,
                    "status": "EVALUATION_ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    mismatch_count = sum(
        1
        for case in results
        for item in case.get("families", [])
        if item.get("comparison") == "MISMATCH"
    )
    inconclusive_count = sum(
        1
        for case in results
        for item in case.get("families", [])
        if item.get("comparison") == "INCONCLUSIVE"
    )
    observed_only_count = sum(
        1 for case in results if case.get("status") == "OBSERVED_ONLY"
    )
    if (
        errors
        or mismatch_count
        or any(x.get("status") == "EVALUATION_ERROR" for x in results)
    ):
        overall = "FAIL"
    elif (
        inconclusive_count
        or observed_only_count
        or any(
            x.get("status")
            in {"INCONCLUSIVE", "PASS_WITH_WARNING", "CAPTURE_NOT_EVALUATED"}
            for x in results
        )
    ):
        overall = "PASS_WITH_WARNINGS"
    else:
        overall = "PASS"

    payload = {
        "schema_version": "1.0",
        "status": overall,
        "manifest": str(manifest_path),
        "capture_report": str(capture_report_path),
        "case_count": len(results),
        "mismatch_count": mismatch_count,
        "inconclusive_count": inconclusive_count,
        "observed_only_count": observed_only_count,
        "errors": errors,
        "cases": results,
        "interpretation": (
            "A mismatch is a failed source-level hypothesis. An inconclusive result is not "
            "a safe negative. Exploratory out-of-scope cases are reported without an expected label."
        ),
    }
    out_path = args.capture_dir / "cwe121-evaluation-report.json"
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    strict = args.strict or os.environ.get("EVIDENCELAB_E2E_STRICT", "0") == "1"
    if (
        errors
        or mismatch_count
        or any(x.get("status") == "EVALUATION_ERROR" for x in results)
    ):
        return 1
    if strict and (inconclusive_count or observed_only_count or overall != "PASS"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
