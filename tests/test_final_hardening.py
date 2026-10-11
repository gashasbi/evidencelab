from __future__ import annotations
import json
from pathlib import Path
import pytest

from evidencelab.models import Graph, Node, Edge
from evidencelab.evaluator import _safe_case_path
from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle


def _dense_graph() -> Graph:
    g = Graph()
    for i in range(20):
        g.add_node(Node(str(i), "CALL"))
    for i in range(1, 20):
        for j in range(i + 1, min(20, i + 5)):
            g.add_edge(Edge(str(i), str(j), "DATAFLOW"))
    return g


def test_bounded_path_search_reports_truncation():
    g = _dense_graph()
    paths, truncated = g.find_paths_bounded(
        ["1"], {"19"}, {"DATAFLOW"}, max_hops=18, limit=100, max_states=10
    )
    assert paths == []
    assert truncated is True


def test_graph_programmatic_default_completeness_is_explicit():
    g = Graph()
    assert g.metadata["completeness"] == "declared"
    assert g.metadata["parse_health"] == "OK"


def test_absolute_graph_base_is_rejected(tmp_path: Path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    root = tmp_path / "bench"
    root.mkdir()
    manifest = root / "benchmark.json"
    manifest.write_text(json.dumps({"graph_base": str(tmp_path), "cases": []}))
    with pytest.raises(ValueError, match="absolute graph_base"):
        _safe_case_path(manifest, "outside.json")


def test_absolute_graph_reference_is_rejected(tmp_path: Path):
    root = tmp_path / "bench"
    root.mkdir()
    target = tmp_path / "outside.json"
    target.write_text("{}")
    manifest = root / "benchmark.json"
    manifest.write_text(json.dumps({"cases": []}))
    with pytest.raises(ValueError, match="absolute graph paths"):
        _safe_case_path(manifest, str(target))


def test_evaluator_continues_after_bad_graph_and_counts_infra(tmp_path: Path):
    from evidencelab.evaluator import run_manifest
    from evidencelab.spec import Pattern

    pattern_raw = {
        "schema_version": "1.0",
        "pattern_id": "infra-case",
        "cwe": "CWE-121",
        "name": "Infra case",
        "version": "1.0.0",
        "language": "C/C++",
        "concepts": {"x": {"selectors": [{"canonical_type_any": ["METHOD"]}]}},
        "slots": [{"id": "x", "concept": "x", "required": True, "max_matches": 10}],
        "claims": [{"id": "c1", "kind": "node", "required": True, "slot": "x"}],
        "witnesses": [
            {
                "id": "w1",
                "required": True,
                "slots": ["x"],
                "claims": ["c1"],
                "counter_claims": [],
            }
        ],
        "provenance": [
            {"kind": "cwe", "id": "cwe-121"},
            {"kind": "literature", "id": "fixture"},
        ],
        "family_id": "infra-case",
        "evidence_contract": {
            "unknown_policy": "unknown",
            "counter_unknown_policy": "block_match",
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
        },
        "semantic_contract": {
            "canonical_graph_required": True,
            "analyzer_independent": True,
        },
        "provenance_policy": {
            "derived_facts_require_inputs": True,
            "literature_linkage": True,
            "artifact_hashes": True,
        },
    }
    pattern_path = tmp_path / "p.json"
    pattern_path.write_text(json.dumps(pattern_raw))
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "nodes": [{"id": "1", "type": "METHOD", "properties": {}}],
                "edges": [],
            }
        )
    )
    bad = tmp_path / "bad.json"
    bad.write_text("{not-json")
    manifest = tmp_path / "benchmark.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "x",
                "cases": [
                    {
                        "id": "good",
                        "graph": "good.json",
                        "expected": "MATCH",
                        "partition": "public",
                    },
                    {
                        "id": "bad",
                        "graph": "bad.json",
                        "expected": "MATCH",
                        "partition": "public",
                    },
                ],
            }
        )
    )
    p = Pattern.load(pattern_path)
    out, metrics, meta = run_manifest(manifest, p)
    assert len(out) == 2
    assert metrics.infra_errors == 1
    assert any(x.case_id == "bad" and x.actual == "INFRA_ERROR" for x in out)


def test_hidden_bundle_rejects_duplicate_graph_content(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    graph = src / "g.json"
    graph.write_text(
        json.dumps(
            {"nodes": [{"id": "1", "type": "CALL", "properties": {}}], "edges": []}
        )
    )
    bench = src / "benchmark.json"
    bench.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {"id": "a", "expected": "MATCH", "graph": "g.json"},
                    {"id": "b", "expected": "MATCH", "graph": "g.json"},
                ],
            }
        )
    )
    out = tmp_path / "hidden"
    seal_hidden_benchmark(bench, out, origin="external-evaluator")
    result = verify_hidden_bundle(out, require_external_origin=True)
    assert result["status"] == "FAIL"
    assert any("duplicate hidden graph content" in x for x in result["errors"])


def test_split_rejects_absolute_graph_reference(tmp_path: Path):
    from evidencelab.splits import split_benchmark
    import json

    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"nodes": [], "edges": []}))
    root = tmp_path / "bench"
    root.mkdir()
    manifest = root / "benchmark.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [
                    {
                        "id": "c1",
                        "expected": "UNKNOWN",
                        "graph": str(outside),
                        "dataset": {"repository": "r1"},
                    }
                ],
            }
        )
    )
    out = tmp_path / "split"
    with pytest.raises(PermissionError, match="absolute graph paths are forbidden"):
        split_benchmark(
            manifest, out, strategy="repository", train=1.0, validation=0.0, test=0.0
        )
