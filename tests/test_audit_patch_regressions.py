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
            "pattern_id": "patch-regression",
            "cwe": "CWE-999",
            "name": "Patch regression fixture",
            "version": "1.0.0",
            "language": "C/C++",
            "family_id": "patch-regression",
            "concepts": {
                "source": {"selectors": [{"type_any": ["CALL"]}]},
                "target": {"selectors": [{"type_any": ["METHOD"]}]},
                "needle": {"selectors": [{"type_any": ["CALL"], "name_any": ["needle"]}]},
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
            "semantic_contract": {"canonical_graph_required": True, "analyzer_independent": True},
            "relevance_policy": {"minimum_sufficient_witness": True},
            "path_budget": {"max_hops": 12},
            "provenance_policy": {"derived_facts_require_inputs": True, "artifact_hashes": True},
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
def test_global_relation_claim_does_not_make_definitive_claim_after_100_candidate_limit(kind):
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    for index in range(101):
        graph.add_node(Node(f"s{index}", "CALL", {"name": f"source{index}"}))
    graph.add_node(Node("target", "METHOD", {"name": "target"}))
    graph.add_edge(Edge("s100", "target", "DATA_FLOW"))

    result = Matcher(graph).run(_relation_pattern(kind))

    assert result.claims[0].status == "UNKNOWN"
    assert result.status == "UNKNOWN"


def test_global_path_absence_checks_all_candidate_pairs():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK", "analysis_completeness": {"dataflow": "COMPLETE"}})
    graph.add_node(Node("s1", "CALL", {"name": "first"}))
    graph.add_node(Node("s2", "CALL", {"name": "second"}))
    graph.add_node(Node("t", "METHOD", {"name": "target"}))
    graph.add_edge(Edge("s2", "t", "DATA_FLOW"))
    pattern = _pattern(
        [{"id": "absence", "kind": "path_absence", "required": True, "source": "s", "target": "t", "edge_types": ["DATA_FLOW"], "max_hops": 2}],
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
            "analysis_attestation": {"level": "ANALYZER_DEGRADED", "status": "DEGRADED"},
        },
    )
    pattern = _pattern(
        [{"id": "node", "kind": "node", "required": True, "slot": "target"}],
        slots=[{"id": "target", "concept": "needle", "required": True}],
        witnesses=[{"id": "w", "slots": ["target"], "claims": ["node"], "required": True}],
    )

    result = Matcher(graph).run(pattern)

    assert result.status == "UNKNOWN"
    assert result.evidence_trace["analysis_incomplete"] is True
    assert any("degraded" in warning.lower() for warning in result.warnings)


def test_hidden_seal_policy_requires_hmac_even_without_caller_flag(tmp_path):
    source = tmp_path / "source"
    (source / "graphs").mkdir(parents=True)
    (source / "graphs" / "g.json").write_text(json.dumps({"nodes": [{"id": "n", "type": "CALL"}], "edges": []}))
    (source / "benchmark.json").write_text(json.dumps({"schema_version": "1.0", "manifest_id": "m", "cases": [{"id": "c", "expected": "UNKNOWN", "graph": "graphs/g.json"}]}))
    bundle = tmp_path / "hidden"
    seal_hidden_benchmark(source / "benchmark.json", bundle, key="secret", require_hmac=True)
    seal = json.loads((bundle / "seal.json").read_text())
    seal.pop("hmac_sha256")
    (bundle / "seal.json").write_text(json.dumps(seal))

    result = verify_hidden_bundle(bundle)

    assert result["status"] == "FAIL"
    assert any("HMAC seal required" in error for error in result["errors"])


def test_hidden_seal_recursively_redacts_sensitive_case_and_manifest_fields(tmp_path):
    source = tmp_path / "source"
    (source / "graphs").mkdir(parents=True)
    (source / "graphs" / "g.json").write_text(json.dumps({"nodes": [{"id": "n", "type": "CALL"}], "edges": []}))
    manifest = {
        "schema_version": "1.0",
        "manifest_id": "m",
        "source_metadata": {"absolute_path": "/private/project"},
        "cases": [{
            "id": "c", "expected": "UNKNOWN", "graph": "graphs/g.json",
            "dataset": {"record": {"source_code": "secret code", "local_path": "/private/file.c"}},
            "provenance": [{"raw_record": "secret raw row"}],
        }],
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


def test_observation_state_preserves_raw_observation_vocabulary_and_rejects_duplicates(tmp_path):
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
    assert any("duplicate observation_id obs-dup" in error for error in result["errors"])


def test_graphml_rejects_dtd_after_long_preamble(tmp_path):
    path = tmp_path / "late-dtd.graphml"
    path.write_text(
        '<?xml version="1.0"?>' + (" " * 9000)
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
