import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from evidencelab.acquire import fetch
from evidencelab.errors import InputFormatError
from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle
from evidencelab.matcher import Matcher
from evidencelab.models import Edge, Graph, Node
from evidencelab.parsers import parse_graphml
from evidencelab.research_records import audit_research_ledgers, record_observation
from evidencelab.spec import Pattern


def _pattern(claims, slots=None, witnesses=None, counters=None):
    return Pattern.from_dict(
        {
            "schema_version": "1.0",
            "pattern_id": "evidence-regression",
            "cwe": "CWE-999",
            "name": "Evidence regression fixture",
            "version": "1.0.0",
            "language": "C/C++",
            "family_id": "evidence-regression",
            "concepts": {
                "source": {"selectors": [{"type_any": ["CALL"]}]},
                "target": {"selectors": [{"type_any": ["METHOD"]}]},
                "needle": {
                    "selectors": [{"type_any": ["CALL"], "name_any": ["needle"]}]
                },
            },
            "slots": slots or [],
            "claims": claims,
            "counter_evidence": counters or [],
            "witnesses": witnesses or [],
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
            "relevance_policy": {"minimum_sufficient_witness": True},
            "path_budget": {"max_hops": 12},
            "provenance_policy": {
                "derived_facts_require_inputs": True,
                "artifact_hashes": True,
            },
        }
    )


def _relation_pattern(kind):
    return _pattern(
        [
            {
                "id": "relation",
                "kind": kind,
                "required": True,
                "source_selector": {"type_any": ["CALL"]},
                "target_selector": {"type_any": ["METHOD"]},
                "relation": "DATA_FLOW",
                "max_hops": 1,
            }
        ]
    )


@pytest.mark.parametrize("kind", ["relation_any", "relation_none"])
def test_global_relation_claim_does_not_make_definitive_claim_after_100_candidate_limit(
    kind,
):
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(101):
        graph.add_node(Node(f"s{index:03d}", "CALL", {"name": f"source{index}"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))
    graph.add_edge(Edge("s100", "target", "DATA_FLOW"))

    result = Matcher(graph).run(_relation_pattern(kind))

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_global_path_absence_checks_all_candidate_pairs():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"dataflow": "COMPLETE"},
        }
    )
    graph.add_node(Node("s1", "CALL", {"name": "first"}))
    graph.add_node(Node("s2", "CALL", {"name": "second"}))
    graph.add_node(Node("t", "METHOD", {"name": "target"}))
    graph.add_edge(Edge("s2", "t", "DATA_FLOW"))
    pattern = _pattern(
        [
            {
                "id": "absence",
                "kind": "path_absence",
                "required": True,
                "source": "s",
                "target": "t",
                "edge_types": ["DATA_FLOW"],
                "max_hops": 2,
            }
        ],
        slots=[
            {"id": "s", "concept": "source", "required": True},
            {"id": "t", "concept": "target", "required": True},
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "DISPROVEN"
    assert result.status == "NO_MATCH"


def test_degraded_analyzer_cannot_produce_definitive_no_match():
    graph = Graph(
        nodes={"other": Node("other", "CALL", {"name": "other"})},
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_attestation": {
                "level": "ANALYZER_DEGRADED",
                "status": "DEGRADED",
            },
        },
    )
    pattern = _pattern(
        [{"id": "node", "kind": "node", "required": True, "slot": "target"}],
        slots=[{"id": "target", "concept": "needle", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["target"], "claims": ["node"], "required": True}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.evidence_trace["analysis_incomplete"] is True
    assert any("degraded" in warning.lower() for warning in result.warnings)


def test_graphml_list_property_risk_preserves_positive_match():
    graph = Graph(
        nodes={"needle": Node("needle", "CALL", {"name": "needle", "size": 16})},
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "loss_risk": {"graphml_lists": True},
        },
    )
    pattern = _pattern(
        [
            {
                "id": "node",
                "kind": "property",
                "required": True,
                "slot": "target",
                "equals": {"size": 16},
            }
        ],
        slots=[{"id": "target", "concept": "needle", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["target"], "claims": ["node"], "required": True}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.evidence_trace["analysis_incomplete"] is False
    assert result.status == "MATCH"
    assert any("property-sensitive claims" in warning for warning in result.warnings)


def test_graphml_list_property_risk_prevents_definitive_no_match():
    graph = Graph(
        nodes={"needle": Node("needle", "CALL", {"name": "needle", "size": 17})},
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "loss_risk": {"graphml_lists": True},
        },
    )
    pattern = _pattern(
        [
            {
                "id": "node",
                "kind": "property",
                "required": True,
                "slot": "target",
                "equals": {"size": 16},
            }
        ],
        slots=[{"id": "target", "concept": "needle", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["target"], "claims": ["node"], "required": True}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.evidence_trace["analysis_incomplete"] is False
    assert any("property-sensitive claims" in warning for warning in result.warnings)


def test_hidden_seal_policy_requires_hmac_even_without_caller_flag(tmp_path):
    source = tmp_path / "source"
    (source / "graphs").mkdir(parents=True)
    (source / "graphs" / "g.json").write_text(
        json.dumps({"nodes": [{"id": "n", "type": "CALL"}], "edges": []})
    )
    (source / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [{"id": "c", "expected": "UNKNOWN", "graph": "graphs/g.json"}],
            }
        )
    )
    bundle = tmp_path / "hidden"
    seal_hidden_benchmark(
        source / "benchmark.json", bundle, key="secret", require_hmac=True
    )
    seal = json.loads((bundle / "seal.json").read_text())
    seal.pop("hmac_sha256")
    (bundle / "seal.json").write_text(json.dumps(seal))

    result = verify_hidden_bundle(bundle)

    assert result["status"] == "FAIL"
    assert any("HMAC seal required" in error for error in result["errors"])


def test_hidden_seal_recursively_redacts_sensitive_case_and_manifest_fields(tmp_path):
    source = tmp_path / "source"
    (source / "graphs").mkdir(parents=True)
    (source / "graphs" / "g.json").write_text(
        json.dumps({"nodes": [{"id": "n", "type": "CALL"}], "edges": []})
    )
    manifest = {
        "schema_version": "1.0",
        "manifest_id": "m",
        "source_metadata": {"absolute_path": "/private/project"},
        "cases": [
            {
                "id": "c",
                "expected": "UNKNOWN",
                "graph": "graphs/g.json",
                "dataset": {
                    "record": {
                        "source_code": "secret code",
                        "local_path": "/private/file.c",
                    }
                },
                "provenance": [{"raw_record": "secret raw row"}],
            }
        ],
    }
    (source / "benchmark.json").write_text(json.dumps(manifest))
    bundle = tmp_path / "hidden"

    seal_hidden_benchmark(source / "benchmark.json", bundle)

    output = json.loads((bundle / "benchmark.json").read_text())
    text = json.dumps(output)
    assert "secret code" not in text
    assert "/private/project" not in text
    assert "/private/file.c" not in text
    assert "secret raw row" not in text
    assert verify_hidden_bundle(bundle)["status"] == "PASS"


def test_observation_state_preserves_raw_observation_vocabulary_and_rejects_duplicates(
    tmp_path,
):
    first = record_observation(
        tmp_path,
        observation_id="obs-1",
        hypothesis_id="h1",
        analyzer="manual-review",
        query="inspect graph",
        artifact="graph.json",
        statement="no edge observed",
        state="ABSENT",
    )
    assert first["state"] == "ABSENT"
    with pytest.raises(ValueError, match="observation state"):
        record_observation(
            tmp_path,
            observation_id="obs-2",
            hypothesis_id="h1",
            analyzer="manual-review",
            query="inspect graph",
            artifact="graph.json",
            statement="not a raw observation state",
            state="PROVEN",
        )
    with pytest.raises(ValueError, match="duplicate observation_id"):
        record_observation(
            tmp_path,
            observation_id="obs-1",
            hypothesis_id="h1",
            analyzer="manual-review",
            query="inspect graph",
            artifact="graph.json",
            statement="duplicate",
            state="OBSERVED",
        )


def test_ledger_audit_reports_duplicate_observation_ids(tmp_path):
    record = record_observation(
        tmp_path,
        observation_id="obs-dup",
        hypothesis_id="h1",
        analyzer="manual-review",
        query="inspect graph",
        artifact="graph.json",
        statement="observed node",
        state="OBSERVED",
    )
    ledger = Path(record["ledger_path"])
    line = ledger.read_text().strip()
    with ledger.open("a") as stream:
        stream.write(line + "\n")

    result = audit_research_ledgers(tmp_path)

    assert result["status"] == "FAIL"
    assert any(
        "duplicate observation_id obs-dup" in error for error in result["errors"]
    )


def test_graphml_rejects_dtd_after_long_preamble(tmp_path):
    path = tmp_path / "late-dtd.graphml"
    path.write_text(
        '<?xml version="1.0"?>'
        + (" " * 9000)
        + '<!DOCTYPE graphml [<!ENTITY sample "value">]>'
        + '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph id="G" edgedefault="directed"><node id="n"/></graph></graphml>',
        encoding="utf-8",
    )

    with pytest.raises(InputFormatError, match="DTD/entity declarations"):
        parse_graphml(path)


def test_resumed_download_restarts_cleanly_when_server_ignores_range(tmp_path):
    payload = b"valid"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        output = tmp_path / "download.bin"
        Path(str(output) + ".part").write_bytes(b"stale")
        result = fetch(
            f"http://127.0.0.1:{server.server_port}/artifact",
            output,
            sha256=hashlib.sha256(payload).hexdigest(),
            resume=True,
            max_bytes=8,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert result["status"] == "PASS"
    assert output.read_bytes() == payload
    assert result["bytes"] == len(payload)


def test_explicit_manifest_missing_dataflow_makes_negative_relation_inconclusive():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"nodes": "COMPLETE", "edges": "COMPLETE"},
        }
    )
    graph.add_node(Node("source", "CALL", {"name": "source"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))

    result = Matcher(graph).run(_relation_pattern("relation_any"))

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"
    assert any("dataflow" in warning.lower() for warning in result.warnings)


def test_partial_dataflow_cannot_produce_definitive_negative_relation():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {
                "nodes": "COMPLETE",
                "edges": "COMPLETE",
                "dataflow": "PARTIAL",
            },
        }
    )
    graph.add_node(Node("source", "CALL", {"name": "source"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))

    result = Matcher(graph).run(_relation_pattern("relation_any"))

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_truncated_slot_cannot_make_witness_no_match_definitive():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("a-other", "CALL", {"name": "other"}))
    graph.add_node(Node("z-needle", "CALL", {"name": "needle"}))
    pattern = _pattern(
        [
            {
                "id": "needle",
                "kind": "node",
                "required": True,
                "slot": "candidate",
                "selector": {"type_any": ["CALL"], "name_any": ["needle"]},
            }
        ],
        slots=[
            {"id": "candidate", "concept": "source", "required": True, "max_matches": 1}
        ],
        witnesses=[
            {"id": "w", "slots": ["candidate"], "claims": ["needle"], "required": True}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.witnesses[0].status == "UNKNOWN"
    assert result.witnesses[0].search_complete is False


def test_hop_cap_is_reported_as_incomplete_not_path_absence():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("a", "CALL", {"name": "a"}))
    graph.add_node(Node("b", "IDENTIFIER", {"name": "b"}))
    graph.add_node(Node("c", "IDENTIFIER", {"name": "c"}))
    graph.add_node(Node("d", "METHOD", {"name": "d"}))
    graph.add_edge(Edge("a", "b", "DATA_FLOW"))
    graph.add_edge(Edge("b", "c", "DATA_FLOW"))
    graph.add_edge(Edge("c", "d", "DATA_FLOW"))
    pattern = _pattern(
        [
            {
                "id": "path",
                "kind": "path",
                "required": True,
                "source": "source",
                "target": "target",
                "edge_types": ["DATA_FLOW"],
                "max_hops": 3,
            }
        ],
        slots=[
            {
                "id": "source",
                "concept": "source",
                "required": True,
                "selector_overrides": [{"name_any": ["a"]}],
            },
            {"id": "target", "concept": "target", "required": True},
        ],
    )

    result = Matcher(graph, hard_max_hops=2).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_global_combination_budget_is_enforced_and_reported():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(4):
        graph.add_node(Node(f"s{index}", "CALL", {"name": f"source{index}"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))
    result = Matcher(graph, max_global_combinations=1).run(
        _relation_pattern("relation_any")
    )

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"
    assert result.evidence_trace["search_budget"]["budget_exhausted"] is True


def test_candidate_truncation_is_deterministic_across_insertion_orders():
    pattern = _pattern(
        [],
        slots=[
            {"id": "candidate", "concept": "source", "required": True, "max_matches": 2}
        ],
    )
    ids = ["z", "a", "m", "b"]
    first = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    second = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for node_id in ids:
        first.add_node(Node(node_id, "CALL", {"name": node_id}))
    for node_id in reversed(ids):
        second.add_node(Node(node_id, "CALL", {"name": node_id}))

    result_a = Matcher(first).run(pattern)
    result_b = Matcher(second).run(pattern)

    assert result_a.slots["candidate"] == result_b.slots["candidate"] == ["a", "b"]


def test_global_compare_truncation_cannot_disprove_binding_after_first_hundred():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(100):
        graph.add_node(
            Node(
                f"a{index:03d}",
                "CALL",
                {"name": f"source{index}", "derived": {"numeric_value": 0}},
            )
        )
    graph.add_node(
        Node("z-last", "CALL", {"name": "source-last", "derived": {"numeric_value": 2}})
    )
    graph.add_node(
        Node("target", "METHOD", {"name": "target", "derived": {"numeric_value": 1}})
    )
    pattern = _pattern(
        [
            {
                "id": "compare",
                "kind": "compare",
                "required": True,
                "left": {"slot": "left", "property": "derived.numeric_value"},
                "right": {"slot": "right", "property": "derived.numeric_value"},
                "operator": ">",
            }
        ],
        slots=[
            {"id": "left", "concept": "source", "required": True, "max_matches": 200},
            {"id": "right", "concept": "target", "required": True},
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_external_cancellation_is_reported_as_incomplete_search():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(3):
        graph.add_node(Node(f"s{index}", "CALL", {"name": f"source{index}"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))

    result = Matcher(graph, cancel_check=lambda: True).run(
        _relation_pattern("relation_any")
    )

    assert result.status == "UNKNOWN"
    assert result.evidence_trace["search_budget"]["budget_exhausted"] is True


def test_explicit_partial_edge_completeness_prevents_negative_relation_proof():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {
                "nodes": "COMPLETE",
                "edges": "PARTIAL",
                "dataflow": "COMPLETE",
            },
        }
    )
    graph.add_node(Node("source", "CALL", {"name": "source"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))
    pattern = _relation_pattern("relation_none")

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_global_negative_claim_is_unknown_when_its_slot_was_truncated():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("a-other", "CALL", {"name": "other", "size": 1}))
    graph.add_node(Node("z-needle", "CALL", {"name": "needle", "size": 2}))
    pattern = _pattern(
        [
            {
                "id": "property",
                "kind": "property",
                "required": True,
                "slot": "candidate",
                "equals": {"name": "needle"},
            }
        ],
        slots=[
            {"id": "candidate", "concept": "source", "required": True, "max_matches": 1}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_missing_property_is_unknown_not_a_definitive_mismatch():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("candidate", "CALL", {"name": "candidate"}))
    pattern = _pattern(
        [
            {
                "id": "property",
                "kind": "property",
                "required": True,
                "slot": "candidate",
                "equals": {"size": 16},
            }
        ],
        slots=[{"id": "candidate", "concept": "source", "required": True}],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_cancelled_candidate_discovery_does_not_report_complete_empty_witness():
    graph = Graph(
        nodes={"needle": Node("needle", "CALL", {"name": "needle"})},
        metadata={"completeness": "full_export", "parse_health": "OK"},
    )
    pattern = _pattern(
        [{"id": "node", "kind": "node", "required": True, "slot": "target"}],
        slots=[{"id": "target", "concept": "needle", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["target"], "claims": ["node"], "required": True}
        ],
    )

    result = Matcher(graph, cancel_check=lambda: True).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.witnesses[0].status == "UNKNOWN"
    assert result.witnesses[0].search_complete is False
    assert result.evidence_trace["witness_search_complete"] is False
    assert result.evidence_trace["search_budget"]["budget_exhausted"] is True


def test_node_absence_requires_explicit_node_and_scope_completeness():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"edges": "COMPLETE"},
        }
    )
    graph.add_node(Node("source", "CALL", {"name": "source"}))
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "selector": {"type_any": ["METHOD"]},
            }
        ]
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"
    assert "nodes=UNKNOWN" in result.claims[0].explanation
    assert "scope=UNKNOWN" in result.claims[0].explanation


def test_relation_absence_requires_explicit_edge_relation_and_scope_completeness():
    graph = Graph(
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"nodes": "COMPLETE", "dataflow": "COMPLETE"},
        }
    )
    graph.add_node(Node("source", "CALL", {"name": "source"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))
    pattern = _relation_pattern("relation_any")

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"
    assert "edges=UNKNOWN" in result.claims[0].explanation
    assert "relations=UNKNOWN" in result.claims[0].explanation
    assert "scope=UNKNOWN" in result.claims[0].explanation


@pytest.mark.parametrize(
    "metadata",
    [
        {"analysis_completeness": {"edges": "COMPLETE"}},
        {"analysis_attestation": {"status": "DEGRADED"}},
        {"analysis_truncated": True},
        {"candidate_truncated": True},
        {"analysis_completeness": ["malformed"]},
    ],
)
def test_witness_node_absence_stays_unknown_when_analysis_is_incomplete(metadata):
    graph = Graph(
        nodes={"source": Node("source", "CALL", {"name": "source"})},
        metadata={"completeness": "full_export", "parse_health": "OK", **metadata},
    )
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "selector": {"type_any": ["METHOD"]},
            }
        ],
        slots=[{"id": "source", "concept": "source", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["source"], "claims": ["missing-method"], "required": True}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.witnesses[0].status == "UNKNOWN"
    assert result.witnesses[0].claims[0].status == "UNKNOWN"


def test_global_node_absence_stays_unknown_when_analysis_is_truncated():
    graph = Graph(
        nodes={"source": Node("source", "CALL", {"name": "source"})},
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_truncated": True,
        },
    )
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "selector": {"type_any": ["METHOD"]},
            }
        ]
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.claims[0].status == "UNKNOWN"


@pytest.mark.parametrize(
    ("parent_present", "expected_claim", "expected_result"),
    [(True, "DISPROVEN", "NO_MATCH"), (False, "PROVEN", "MATCH")],
)
def test_parent_method_path_absence_has_correct_polarity(
    parent_present, expected_claim, expected_result
):
    properties = {"name": "target"}
    if parent_present:
        properties["derived"] = {"parent_method_node": "source-node"}
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("source-node", "CALL", {"name": "source"}))
    graph.add_node(Node("target-node", "METHOD", properties))
    pattern = _pattern(
        [
            {
                "id": "no-parent-relation",
                "kind": "path_absence",
                "required": True,
                "source": "source",
                "target": "target",
                "relation": "PARENT_METHOD",
            }
        ],
        slots=[
            {"id": "source", "concept": "source", "required": True},
            {"id": "target", "concept": "target", "required": True},
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == expected_claim
    assert result.status == expected_result


@pytest.mark.parametrize(
    ("min_count", "max_count", "expected"),
    [(None, 2, "UNKNOWN"), (2, None, "UNKNOWN"), (1, None, "PROVEN")],
)
def test_cardinality_claim_respects_truncated_candidate_slots(
    min_count, max_count, expected
):
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(3):
        graph.add_node(Node(f"source-{index}", "CALL", {"name": f"source{index}"}))
    pattern = _pattern(
        [
            {
                "id": "count",
                "kind": "cardinality",
                "required": True,
                "slot": "candidate",
                "min_count": min_count,
                "max_count": max_count,
            }
        ],
        slots=[
            {"id": "candidate", "concept": "source", "required": True, "max_matches": 1}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == expected
    if expected == "UNKNOWN":
        assert result.status == "UNKNOWN"


def test_global_node_absence_cannot_prove_absence_after_cancellation():
    graph = Graph(
        nodes={"source": Node("source", "CALL", {"name": "source"})},
        metadata={"completeness": "full_export", "parse_health": "OK"},
    )
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "selector": {"type_any": ["METHOD"]},
            }
        ]
    )

    result = Matcher(graph, cancel_check=lambda: True).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_matching_node_disproves_node_absence_even_when_graph_is_incomplete():
    graph = Graph(
        nodes={
            "source": Node("source", "CALL", {"name": "source"}),
            "method": Node("method", "METHOD", {"name": "present-method"}),
        },
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"nodes": "PARTIAL"},
        },
    )
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "selector": {"type_any": ["METHOD"]},
            }
        ]
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "DISPROVEN"
    assert result.status == "UNKNOWN"


def test_cardinality_upper_bound_requires_complete_node_scope_manifest():
    graph = Graph(
        nodes={"source": Node("source", "CALL", {"name": "source"})},
        metadata={
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_completeness": {"dataflow": "COMPLETE"},
        },
    )
    pattern = _pattern(
        [
            {
                "id": "count",
                "kind": "cardinality",
                "required": True,
                "slot": "candidate",
                "max_count": 2,
            }
        ],
        slots=[{"id": "candidate", "concept": "source", "required": True}],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_hidden_verifier_reports_path_traversal_without_crashing(tmp_path):
    source = tmp_path / "source"
    (source / "graphs").mkdir(parents=True)
    (source / "graphs" / "g.json").write_text(
        json.dumps({"nodes": [{"id": "n", "type": "CALL"}], "edges": []})
    )
    (source / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [{"id": "c", "expected": "UNKNOWN", "graph": "graphs/g.json"}],
            }
        )
    )
    bundle = tmp_path / "hidden"
    seal_hidden_benchmark(source / "benchmark.json", bundle)
    manifest_path = bundle / "benchmark.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][0]["graph"] = "../../outside.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_hidden_bundle(bundle)

    assert result["status"] == "FAIL"
    assert any("invalid hidden graph path" in error for error in result["errors"])


def test_zero_witness_alternative_limit_is_normalized_safely():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("needle", "CALL", {"name": "needle"}))
    pattern = _pattern(
        [{"id": "node", "kind": "node", "required": True, "slot": "candidate"}],
        slots=[{"id": "candidate", "concept": "needle", "required": True}],
        witnesses=[
            {"id": "w", "slots": ["candidate"], "claims": ["node"], "required": True}
        ],
    )

    result = Matcher(graph, max_witness_alternatives=0).run(pattern)

    assert result.status == "MATCH"
    assert result.witnesses[0].status == "MATCH"


def test_global_node_absence_cannot_prove_absence_from_truncated_slot():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    graph.add_node(Node("a-other", "METHOD", {"name": "other"}))
    graph.add_node(Node("z-needle", "METHOD", {"name": "needle"}))
    pattern = _pattern(
        [
            {
                "id": "missing-method",
                "kind": "node_absence",
                "required": True,
                "slot": "candidate",
                "selector": {"type_any": ["METHOD"], "name_any": ["needle"]},
            }
        ],
        slots=[
            {"id": "candidate", "concept": "target", "required": True, "max_matches": 1}
        ],
    )

    result = Matcher(graph).run(pattern)

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"
