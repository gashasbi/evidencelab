from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidencelab import SCHEMA_VERSION, __version__
from evidencelab.migration import migrate_pattern_to_current
from evidencelab.spec import Pattern

ROOT = Path(__file__).resolve().parents[1]


def test_public_contract_is_single_and_unversioned_by_history():
    assert __version__ == "1.0.0"
    assert SCHEMA_VERSION == "1.0"
    schema_files = sorted(p.name for p in (ROOT / "schemas").glob("*.schema.json"))
    assert schema_files
    assert all(
        not any(f"-{old}.schema" in name for old in ("7", "8", "9"))
        for name in schema_files
    )
    assert not (ROOT / "legacy").exists()
    assert len(schema_files) == len(set(schema_files))


def test_import_normalizes_older_pattern_and_marks_research_review(tmp_path: Path):
    raw = json.loads(
        (ROOT / "examples/cwe-121/families/fixed-write/pattern.json").read_text()
    )
    raw["schema_version"] = "legacy"
    raw["version"] = "draft"
    raw.pop("family_id", None)
    raw.pop("evidence_contract", None)
    raw.pop("semantic_contract", None)
    raw.pop("relevance_policy", None)
    raw.pop("path_budget", None)
    raw.pop("provenance_policy", None)
    raw["metadata"].pop("evidence_definition_version", None)
    for concept in raw["concepts"].values():
        for selector in concept.get("selectors", []):
            selector.pop("canonical_type_any", None)
            selector.pop("canonical_type_all", None)
    source = tmp_path / "input.json"
    output = tmp_path / "normalized.json"
    source.write_text(json.dumps(raw), encoding="utf-8")

    result = migrate_pattern_to_current(source, output)
    normalized = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "PASS"
    assert normalized["schema_version"] == SCHEMA_VERSION
    assert normalized["version"] == __version__
    assert normalized["metadata"]["migration_status"] == "MIGRATED_REQUIRES_REVIEW"
    assert normalized["evidence_contract"]["tri_state"] is True
    assert normalized["semantic_contract"]["analyzer_independent"] is True
    assert normalized["provenance_policy"]["derived_facts_require_inputs"] is True
    Pattern.load(output)


def test_import_rejects_malformed_input_without_partial_output(tmp_path: Path):
    source = tmp_path / "broken.json"
    output = tmp_path / "normalized.json"
    source.write_text(
        json.dumps({"schema_version": "legacy", "pattern_id": "missing"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="required field"):
        migrate_pattern_to_current(source, output)
    assert not output.exists()


def test_performance_report_has_tail_latency_and_memory_fields(tmp_path: Path):
    from evidencelab.performance import profile_pattern
    from evidencelab.family import init_evidence_family
    from evidencelab.project import init_research_project

    graph = tmp_path / "g.json"
    graph.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "nodes": [
                    {"id": "1", "type": "METHOD", "properties": {}},
                    {"id": "2", "type": "CALL", "properties": {}},
                ],
                "edges": [
                    {"source": "1", "target": "2", "type": "AST", "properties": {}}
                ],
            }
        ),
        encoding="utf-8",
    )
    project = init_research_project("CWE-121", tmp_path / "research")
    family = init_evidence_family(project, "perf")
    raw = json.loads((family / "pattern.json").read_text(encoding="utf-8"))
    raw["slots"] = [{"id": "x", "concept": "x", "required": True, "max_matches": 10}]
    raw["claims"] = [{"id": "c1", "kind": "node", "required": True, "slot": "x"}]
    raw["concepts"] = {"x": {"selectors": [{"canonical_type_any": ["METHOD"]}]}}
    raw["witnesses"] = [
        {
            "id": "w",
            "required": True,
            "slots": ["x"],
            "claims": ["c1"],
            "counter_claims": [],
        }
    ]
    raw["provenance"] = [
        {"kind": "cwe", "id": "cwe"},
        {"kind": "literature", "id": "lit"},
    ]
    (family / "pattern.json").write_text(json.dumps(raw), encoding="utf-8")
    pattern = Pattern.load(family / "pattern.json")
    benchmark = {
        "schema_version": SCHEMA_VERSION,
        "cases": [
            {
                "id": "c1",
                "graph": "g.json",
                "expected": "NO_MATCH",
                "partition": "public",
                "negative_evidence": "no required witness",
            }
        ],
        "split": {"strategies": ["repository", "chronological"]},
    }
    (family / "g.json").write_text(graph.read_text(encoding="utf-8"), encoding="utf-8")
    (family / "benchmark.json").write_text(json.dumps(benchmark), encoding="utf-8")
    report = profile_pattern(
        family / "benchmark.json",
        pattern,
        max_case_seconds=5,
        max_case_memory_bytes=2_000_000_000,
    )
    assert "p99" in report["case_seconds"]
    assert "max_case_memory_bytes" in report["resource"]


def test_profile_dimension_policy_is_independent_from_reference_corpus():
    from evidencelab.evaluator import audit_benchmark_manifest

    dev = json.loads(
        (ROOT / "profiles/development-c-cpp-joern.json").read_text(encoding="utf-8")
    )
    pub = json.loads(
        (ROOT / "profiles/research-publication-c-cpp-joern.json").read_text(
            encoding="utf-8"
        )
    )
    pattern = Pattern.load(ROOT / "examples/cwe-121/families/fixed-write/pattern.json")
    benchmark = ROOT / "examples/cwe-121/families/fixed-write/benchmark.json"
    assert (
        audit_benchmark_manifest(benchmark, pattern, required_dimensions=set())[
            "status"
        ]
        == "PASS"
    )
    assert (
        audit_benchmark_manifest(
            benchmark, pattern, required_dimensions=set(pub["required_dimensions"])
        )["status"]
        == "FAIL"
    )
    assert dev.get("enforce_quality_gates") is not True
    assert pub.get("enforce_quality_gates") is True
