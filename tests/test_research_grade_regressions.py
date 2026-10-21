from pathlib import Path
from evidencelab.benchmark_quality import quality_audit

ROOT = Path(__file__).resolve().parents[1]


def test_public_reference_cwe120_does_not_fake_publication_pass():
    profile = __import__("json").loads(
        (ROOT / "profiles/research-publication-c-cpp-joern.json").read_text()
    )
    family = ROOT / "examples/cwe-120/families/fixed-extent-overflow"
    gates = profile["gates"]
    r = quality_audit(
        family / "benchmark.json",
        min_case_count=gates["min_total"],
        min_positive=gates["min_positive"],
        min_negative=gates["min_negative"],
        min_unknown=gates["min_unknown"],
        min_real_world=profile["min_real_world_cases"],
        required_dimensions=set(profile["required_dimensions"]),
        dimension_minima=profile["dimension_minima"],
        min_dataset_sources=profile["min_dataset_sources"],
        min_repositories=profile["min_repositories"],
        min_projects=profile["min_projects"],
        min_cves=profile["min_cves"],
    )
    assert r["status"] == "FAIL"
    assert any("total cases below minimum" in e for e in r["errors"])
    assert profile["require_hidden_validation"] is True


def test_research_init_is_explicit_scaffold():
    import tempfile
    from evidencelab.project import init_research_project

    with tempfile.TemporaryDirectory() as td:
        root = init_research_project("CWE-121", Path(td) / "research")
        from evidencelab.research_package import audit_research_package

        assert audit_research_package(root)["status"] == "SCAFFOLD"


def test_witness_search_early_match_is_not_incoherent():
    from evidencelab.evaluator import run_manifest
    from evidencelab.spec import Pattern
    from evidencelab.evidence_quality import compute_evidence_quality

    p = ROOT / "examples/cwe-120/families/fixed-extent-overflow"
    results, _, _ = run_manifest(
        p / "benchmark.json", Pattern.load(p / "pattern.json"), reveal=True
    )
    q = compute_evidence_quality(results, Pattern.load(p / "pattern.json"))
    assert q["witness_coherence_rate"] == 1.0
    assert q["witness_search_complete_rate"] is not None


def test_registry_supports_pinned_multiple_artifacts():
    raw = __import__("json").loads((ROOT / "datasets/registry.json").read_text())
    prime = next(x for x in raw["datasets"] if x["id"] == "primevul")
    sec = next(x for x in raw["datasets"] if x["id"] == "secvuleval")
    assert {a["id"] for a in prime["artifacts"]} >= {"test-jsonl", "test-paired-jsonl"}
    assert sec["artifacts"][0]["kind"] == "parquet"


def test_ambiguous_generic_labels_remain_unknown():
    from evidencelab.datasets import _target_label

    assert _target_label("positive") == "UNKNOWN"
    assert _target_label("negative") == "UNKNOWN"
    assert _target_label("1") == "MATCH"
    assert _target_label("0") == "NO_MATCH"


def test_registry_multi_artifact_requires_explicit_selection(tmp_path):
    import json
    from evidencelab.acquire import fetch_registry_dataset

    registry = json.loads((ROOT / "datasets/registry.json").read_text())
    rpath = tmp_path / "registry.json"
    rpath.write_text(json.dumps(registry))
    out = tmp_path / "x.bin"
    r = fetch_registry_dataset(rpath, "primevul", out)
    assert r["status"] == "FAIL"
    assert "multiple artifacts" in r["error"]


def test_registry_artifact_selection_passes_pinned_url_and_sha(tmp_path, monkeypatch):
    import json
    import evidencelab.acquire as acq

    registry = json.loads((ROOT / "datasets/registry.json").read_text())
    rpath = tmp_path / "registry.json"
    rpath.write_text(json.dumps(registry))
    seen = {}

    def fake_fetch(url, out, sha256, timeout, resume):
        seen.update(
            url=url, out=str(out), sha256=sha256, timeout=timeout, resume=resume
        )
        return {"status": "PASS", "sha256": sha256}

    monkeypatch.setattr(acq, "fetch", fake_fetch)
    out = tmp_path / "x.jsonl"
    r = acq.fetch_registry_dataset(rpath, "primevul", out, artifact_id="test-jsonl")
    assert r["status"] == "PASS"
    assert seen["url"].startswith("https://huggingface.co/")
    assert seen["sha256"].startswith("c9dcab5e")


def test_hidden_bundle_detects_graph_tampering(tmp_path):
    import json
    from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle

    src = tmp_path / "src"
    (src / "graphs").mkdir(parents=True)
    graph = next(
        (ROOT / "examples/cwe-120/families/fixed-extent-overflow/graphs").glob("*.json")
    )
    import shutil

    shutil.copy2(graph, src / "graphs" / "g.json")
    (src / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "format": "evidencelab-benchmark",
                "manifest_id": "h-test",
                "cases": [
                    {
                        "id": "h1",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                        "tags": ["unknown"],
                        "dimensions": ["analysis_completeness"],
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )
    bundle = tmp_path / "bundle"
    assert seal_hidden_benchmark(src / "benchmark.json", bundle)["status"] == "PASS"
    assert verify_hidden_bundle(bundle)["status"] == "PASS"
    gp = next((bundle / "graphs").glob("*.json"))
    gp.write_bytes(gp.read_bytes() + b"\n")
    r = verify_hidden_bundle(bundle)
    assert r["status"] == "FAIL"
    assert any(
        "hidden graph sha256 mismatch" in x or "hidden bundle sha256 mismatch" in x
        for x in r["errors"]
    )


def test_hidden_hmac_verification_rejects_wrong_key(tmp_path):
    import json, os, shutil
    from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle

    src = tmp_path / "src"
    (src / "graphs").mkdir(parents=True)
    graph = next(
        (ROOT / "examples/cwe-120/families/fixed-extent-overflow/graphs").glob("*.json")
    )
    shutil.copy2(graph, src / "graphs" / "g.json")
    (src / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "format": "evidencelab-benchmark",
                "cases": [
                    {
                        "id": "h",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                    }
                ],
            },
            indent=2,
        )
    )
    bundle = tmp_path / "bundle"
    assert (
        seal_hidden_benchmark(src / "benchmark.json", bundle, key="correct-key")[
            "status"
        ]
        == "PASS"
    )
    assert verify_hidden_bundle(bundle, "correct-key")["status"] == "PASS"
    assert verify_hidden_bundle(bundle, "wrong-key")["status"] == "FAIL"


def test_sec_vul_eval_parquet_requires_optional_dependency(tmp_path):
    import pytest
    from evidencelab.datasets import _read_rows

    p = tmp_path / "x.parquet"
    p.write_bytes(b"not-a-parquet")
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="optional pyarrow dependency"):
            _read_rows(p)


def test_symbolic_range_witness_replays_independently():
    from evidencelab.witness_validator import validate_benchmark_matches
    from evidencelab.spec import Pattern

    p = ROOT / "examples/cwe-120/families/symbolic-range-overflow"
    r = validate_benchmark_matches(
        p / "benchmark.json",
        Pattern.load(p / "pattern.json"),
        max_cases=2,
        only_status="MATCH",
    )
    assert r["status"] == "PASS", r
    assert r["passed_cases"] == 2


def test_semantic_diversity_reports_unreadable_graphs(tmp_path):
    import json

    manifest = {
        "schema_version": "1.0",
        "format": "evidencelab-benchmark",
        "manifest_id": "semantic-diversity-regression",
        "cases": [
            {
                "id": "missing-graph",
                "expected": "UNKNOWN",
                "graph": "graphs/missing.json",
            },
            {
                "id": "no-graph",
                "expected": "UNKNOWN",
            },
        ],
    }
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = quality_audit(path)
    diversity = result["semantic_diversity"]

    assert diversity["graph_count"] == 0
    assert diversity["effective_semantic_sample_size"] == 0
    assert diversity.get("graph_errors"), (
        "Unreadable graph files must be reported, not silently skipped"
    )
    assert any(
        error.get("case_id") == "missing-graph"
        for error in diversity["graph_errors"]
    )

def test_semantic_diversity_excludes_invalid_graphs(tmp_path):
    import json
    from evidencelab.benchmark_quality import _semantic_diversity

    manifest = {
        "schema_version": "1.0",
        "format": "evidencelab-benchmark",
        "manifest_id": "invalid-semantic-graph",
        "cases": [
            {"id": "empty", "expected": "UNKNOWN", "graph": "graphs/empty.json"},
        ],
    }
    graphs = tmp_path / "graphs"
    graphs.mkdir()
    (graphs / "empty.json").write_text(
        json.dumps({"nodes": [], "edges": []}), encoding="utf-8"
    )
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _semantic_diversity(path, manifest["cases"])

    assert result["graph_count"] == 0
    assert result["effective_semantic_sample_size"] == 0
    assert len(result["invalid_graphs"]) == 1
    assert result["invalid_graphs"][0]["case_id"] == "empty"


def test_semantic_diversity_retains_degraded_nonempty_graphs(tmp_path):
    import json
    from evidencelab.benchmark_quality import _semantic_diversity

    manifest = {
        "schema_version": "1.0",
        "format": "evidencelab-benchmark",
        "manifest_id": "degraded-semantic-graph",
        "cases": [
            {"id": "degraded", "expected": "UNKNOWN", "graph": "graphs/partial.json"},
        ],
    }
    graphs = tmp_path / "graphs"
    graphs.mkdir()
    (graphs / "partial.json").write_text(
        json.dumps({
            "nodes": [
                {"id": "n1", "type": "CALL", "properties": {"name": "unknown_call"}}
            ],
            "edges": [],
            "metadata": {"parse_health": "DEGRADED", "completeness": "partial"},
        }),
        encoding="utf-8",
    )
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _semantic_diversity(path, manifest["cases"])

    assert result["graph_count"] == 1
    assert result["effective_semantic_sample_size"] == 1
    assert result["invalid_graphs"] == []



def test_quality_audit_fails_when_graph_is_invalid(tmp_path):
    import json

    graphs = tmp_path / "graphs"
    graphs.mkdir()
    (graphs / "empty.json").write_text(
        json.dumps({"nodes": [], "edges": []}),
        encoding="utf-8",
    )

    manifest = {
        "schema_version": "1.0",
        "format": "evidencelab-benchmark",
        "manifest_id": "invalid-graph-audit-regression",
        "cases": [
            {
                "id": "invalid-empty-graph",
                "expected": "UNKNOWN",
                "graph": "graphs/empty.json",
            }
        ],
    }

    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = quality_audit(path)

    assert result["status"] == "FAIL"
    assert any(
        "semantic graph invalid for case 'invalid-empty-graph'" in error
        for error in result["errors"]
    )



def _load_semantic_fingerprint_fixture(relative_path):
    from pathlib import Path
    from evidencelab.parsers import parse_graph

    return parse_graph(Path(__file__).resolve().parents[1] / relative_path)


def test_semantic_fingerprint_distinguishes_numeric_literal_values():
    from copy import deepcopy
    from evidencelab.canonical import semantic_graph_fingerprint

    graph = _load_semantic_fingerprint_fixture(
        "examples/cwe-121/graphs/vulnerable.json"
    )
    literal = next(n for n in graph.nodes.values() if n.type == "LITERAL")
    original_code = literal.properties.get(
        "code", literal.properties.get("CODE")
    )
    assert original_code is not None

    changed = deepcopy(graph)
    changed_literal = next(
        n for n in changed.nodes.values() if n.type == "LITERAL"
    )
    if "code" in changed_literal.properties or "CODE" not in changed_literal.properties:
        changed_literal.properties["code"] = "31"
    else:
        changed_literal.properties["CODE"] = "31"

    assert semantic_graph_fingerprint(graph) != semantic_graph_fingerprint(changed)


def test_semantic_fingerprint_distinguishes_call_targets():
    from copy import deepcopy
    from evidencelab.canonical import semantic_graph_fingerprint

    graph = _load_semantic_fingerprint_fixture(
        "examples/cwe-121/graphs/vulnerable.json"
    )
    changed = deepcopy(graph)
    call = next(n for n in changed.nodes.values() if n.type == "CALL")
    call.properties["name"] = "strcpy"
    call.properties["methodFullName"] = "strcpy"
    derived = call.properties.setdefault("derived", {})
    derived["name"] = "strcpy"
    derived["call_name"] = "strcpy"

    assert semantic_graph_fingerprint(graph) != semantic_graph_fingerprint(changed)


def test_semantic_fingerprint_distinguishes_memory_capacity_values():
    from copy import deepcopy
    from evidencelab.canonical import semantic_graph_fingerprint

    graph = _load_semantic_fingerprint_fixture(
        "examples/cwe-121/graphs/vulnerable.json"
    )
    capacity_32 = deepcopy(graph)
    capacity_64 = deepcopy(graph)

    local_32 = next(n for n in capacity_32.nodes.values() if n.type == "LOCAL")
    local_64 = next(n for n in capacity_64.nodes.values() if n.type == "LOCAL")

    derived_32 = local_32.properties.setdefault("derived", {})
    derived_64 = local_64.properties.setdefault("derived", {})

    derived_32["memory_capacity"] = 32
    derived_64["memory_capacity"] = 64
    derived_32["memory_capacity_known"] = True
    derived_64["memory_capacity_known"] = True
    derived_32["capacity_unit"] = "BYTES"
    derived_64["capacity_unit"] = "BYTES"

    assert semantic_graph_fingerprint(capacity_32) != semantic_graph_fingerprint(
        capacity_64
    )


def test_semantic_fingerprint_distinguishes_argument_roles():
    from copy import deepcopy
    from evidencelab.canonical import semantic_graph_fingerprint

    graph = _load_semantic_fingerprint_fixture(
        "examples/cwe-120/families/"
        "unbounded-format-output/graphs/adv_01.json"
    )
    source_node = next(
        n for n in graph.nodes.values()
        if (n.properties.get("derived") or {}).get("argument_role") == "source"
    )

    changed = deepcopy(graph)
    changed_node = changed.nodes[source_node.id]
    changed_node.properties.setdefault("derived", {})["argument_role"] = "destination"

    assert semantic_graph_fingerprint(graph) != semantic_graph_fingerprint(changed)


def test_semantic_fingerprint_ignores_node_ids_and_method_names():
    from copy import deepcopy
    from evidencelab.canonical import semantic_graph_fingerprint

    graph = _load_semantic_fingerprint_fixture(
        "examples/cwe-120/families/"
        "unbounded-format-output/graphs/adv_01.json"
    )
    changed = deepcopy(graph)

    old_items = list(changed.nodes.items())
    mapping = {
        old_id: f"renamed_node_{index}"
        for index, (old_id, _) in enumerate(old_items)
    }

    for old_id, node in old_items:
        node.id = mapping[old_id]
        if node.type == "METHOD":
            node.properties["name"] = "renamed_sample_method"
            node.properties["code"] = "renamed_sample_method"

    changed.nodes = {
        mapping[old_id]: node
        for old_id, node in old_items
    }

    for edge in changed.edges:
        edge.source = mapping[edge.source]
        edge.target = mapping[edge.target]

    assert semantic_graph_fingerprint(graph) == semantic_graph_fingerprint(changed)


def test_quality_audit_does_not_invent_independence_clusters(tmp_path):
    import json
    from evidencelab.benchmark_quality import quality_audit

    manifest = {
        "schema_version": "1.0",
        "format": "evidencelab-benchmark",
        "manifest_id": "missing-cluster-provenance",
        "cases": [
            {"id": "unique-a", "expected": "MATCH"},
            {"id": "unique-b", "expected": "NO_MATCH"},
            {
                "id": "repo-a-1",
                "expected": "MATCH",
                "dataset": {"repository": "repo-a"},
            },
            {
                "id": "repo-a-2",
                "expected": "NO_MATCH",
                "dataset": {"repository": "repo-a"},
            },
        ],
    }
    path = tmp_path / "benchmark.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    report = quality_audit(path)
    clusters = report["independence_clusters"]

    assert clusters["count"] == 1
    assert clusters["sizes"] == [2]
    assert clusters["assigned_cases"] == 2
    assert clusters["unassigned_cases"] == 2
