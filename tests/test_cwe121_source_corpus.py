from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from scripts.cwe121_source_evaluate import (
    capture_coverage_errors,
    classify_evaluation,
    decision_is_complete,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "examples/cwe-121"
MANIFEST = PACKAGE / "source-cases.json"


def test_cwe121_source_manifest_is_complete_and_well_formed():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["format"] == "evidencelab-cwe121-source-corpus"
    assert set(data["families"]) == {"fixed-write", "unbounded-copy"}

    ids = [case["id"] for case in data["cases"]]
    sources = [case["source"] for case in data["cases"]]
    assert len(ids) == len(set(ids))
    assert len(sources) == len(set(sources))

    allowed = {"MATCH", "NO_MATCH", "UNKNOWN", "PARTIAL"}
    for family, relpath in data["families"].items():
        assert (PACKAGE / relpath).is_file(), family
    for case in data["cases"]:
        assert (PACKAGE / case["source"]).is_file(), case["id"]
        assert Path(case["source"]).suffix in {".c", ".cpp"}
        assert case["scope"] in {"in_scope", "exploratory_out_of_scope"}
        assert isinstance(case.get("expected"), dict)
        assert set(case["expected"]) <= set(data["families"])
        assert set(case["expected"].values()) <= allowed
        if case["scope"] == "exploratory_out_of_scope":
            assert case["expected"] == {}


def test_all_source_cases_have_syntax_checks_when_compilers_exist():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for case in data["cases"]:
        source = PACKAGE / case["source"]
        suffix = source.suffix
        compiler = shutil.which("cc" if suffix == ".c" else "c++")
        if compiler is None:
            continue
        standard = "-std=c11" if suffix == ".c" else "-std=c++17"
        proc = subprocess.run(
            [compiler, standard, "-fsyntax-only", str(source)],
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, (
            f"{case['id']} failed syntax check:\n{proc.stdout}\n{proc.stderr}"
        )


def test_incomplete_graph_never_turns_a_no_match_into_a_definitive_result():
    trace = {
        "analysis_incomplete": True,
        "witness_search_complete": True,
        "graph_complete_for_absence": False,
    }
    assert not decision_is_complete("NO_MATCH", trace)
    assert classify_evaluation("NO_MATCH", "NO_MATCH", trace) == "INCONCLUSIVE"


def test_complete_expected_outcomes_are_compared_exactly():
    trace = {
        "analysis_incomplete": False,
        "witness_search_complete": True,
        "graph_complete_for_absence": True,
    }
    assert decision_is_complete("NO_MATCH", trace)
    assert classify_evaluation("NO_MATCH", "NO_MATCH", trace) == "PASS"
    assert classify_evaluation("MATCH", "NO_MATCH", trace) == "MISMATCH"
    assert classify_evaluation("UNKNOWN", "UNKNOWN", trace) == "PASS"


def test_out_of_scope_source_is_observed_not_mislabeled():
    trace = {
        "analysis_incomplete": False,
        "witness_search_complete": True,
        "graph_complete_for_absence": True,
    }
    assert classify_evaluation(None, "NO_MATCH", trace) == "OBSERVED_ONLY"


def test_capture_coverage_detects_missing_manifest_cases():
    manifest = [
        {"id": "P01", "source": "corpus/source/P01.c"},
        {"id": "N01", "source": "corpus/source/N01.c"},
    ]
    captured = [{"source": "/tmp/capture/P01.c", "status": "PASS"}]

    errors = capture_coverage_errors(manifest, captured)
    assert any("N01.c" in error and "missing" in error for error in errors)


def test_capture_coverage_detects_duplicate_and_unexpected_cases():
    manifest = [{"id": "P01", "source": "corpus/source/P01.c"}]
    captured = [
        {"source": "/tmp/one/P01.c", "status": "PASS"},
        {"source": "/tmp/two/P01.c", "status": "PASS"},
        {"source": "/tmp/extra/EXTRA.c", "status": "PASS"},
    ]

    errors = capture_coverage_errors(manifest, captured)
    assert any("duplicate source in capture report: P01.c" == e for e in errors)
    assert any("source is absent from source-cases.json: EXTRA.c" == e for e in errors)
