from evidencelab.models import Graph, Node
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern

def _pattern(required_dimensions=None, selector_name="needle", include_witnesses=True):
    dims = required_dimensions or []
    return Pattern.from_dict({
        "schema_version":"1.0","pattern_id":"qa-tristate","cwe":"CWE-999",
        "name":"QA tri-state fixture","version":"1.0.0","language":"C/C++",
        "family_id":"qa-tristate",
        "concepts":{"target":{"selectors":[{"type_any":["CALL"],"name_any":[selector_name]}]}},
        "slots":[{"id":"target","concept":"target","required":True}],
        "claims":[{"id":"node","kind":"node","required":True,"slot":"target"}],
        "counter_evidence":[],
        "witnesses":[{"id":"w1","slots":["target"],"claims":["node"],"required":True}] if include_witnesses else [],
        "evidence_contract":{"unknown_policy":"unknown","counter_unknown_policy":"block_match",
            "tri_state":True,"counter_evidence_binding":"same_witness","minimum_sufficient_witness":True,
            "required_analysis_dimensions":dims},
        "semantic_contract":{"canonical_graph_required":True,"analyzer_independent":True,
            "required_analysis_dimensions":dims},
        "relevance_policy":{"minimum_sufficient_witness":True},"path_budget":{"max_hops":12},
        "provenance_policy":{"derived_facts_require_inputs":True,"artifact_hashes":True},
    })

def test_positive_fixture_matches():
    g=Graph(metadata={"completeness":"full_export","parse_health":"OK"})
    g.add_node(Node("c","CALL",{"name":"needle"}))
    r=Matcher(g).run(_pattern())
    assert r.status == "MATCH", r.to_dict()

def test_complete_graph_exact_nonmatch_is_no_match():
    g=Graph(metadata={"completeness":"full_export","parse_health":"OK"})
    g.add_node(Node("c","CALL",{"name":"other"}))
    r=Matcher(g).run(_pattern())
    assert r.status == "NO_MATCH", r.to_dict()

def test_partial_graph_absence_is_not_definitive():
    g=Graph(metadata={"completeness":"partial","parse_health":"OK"})
    g.add_node(Node("c","CALL",{"name":"other"}))
    r=Matcher(g).run(_pattern())
    assert r.status in {"UNKNOWN","PARTIAL"}, r.to_dict()

def test_missing_required_dimension_suppresses_definitive_match():
    g=Graph(metadata={"completeness":"full_export","parse_health":"OK",
        "analysis_completeness":{"dataflow":"UNKNOWN"}})
    g.add_node(Node("c","CALL",{"name":"needle"}))
    r=Matcher(g).run(_pattern(required_dimensions=["dataflow"]))
    assert r.status in {"UNKNOWN","PARTIAL"}, r.to_dict()
    assert r.to_dict().get("evidence_trace",{}).get("analysis_incomplete") is True

def test_complete_required_dimension_allows_match():
    g=Graph(metadata={"completeness":"full_export","parse_health":"OK",
        "analysis_completeness":{"dataflow":"COMPLETE"}})
    g.add_node(Node("c","CALL",{"name":"needle"}))
    r=Matcher(g).run(_pattern(required_dimensions=["dataflow"]))
    assert r.status == "MATCH", r.to_dict()
def test_required_attestation_suppresses_definitive_match_when_missing():
    g = Graph(metadata={"completeness":"full_export","parse_health":"OK"})
    g.add_node(Node("c","CALL",{"name":"needle"}))
    r = Matcher(g, require_analyzer_attestation=True).run(_pattern())
    assert r.status in {"UNKNOWN","PARTIAL"}, r.to_dict()
    trace = r.to_dict().get("evidence_trace", {})
    assert trace.get("analysis_incomplete") is True

def test_analysis_truncation_suppresses_definitive_match():
    g = Graph(metadata={"completeness":"full_export","parse_health":"OK","analysis_truncated":True})
    g.add_node(Node("c","CALL",{"name":"needle"}))
    r = Matcher(g).run(_pattern())
    assert r.status in {"UNKNOWN","PARTIAL"}, r.to_dict()


def test_analysis_truncation_suppresses_match_without_witnesses():
    g = Graph(metadata={"completeness": "full_export", "parse_health": "OK", "analysis_truncated": True})
    g.add_node(Node("c", "CALL", {"name": "needle"}))
    r = Matcher(g).run(_pattern(include_witnesses=False))
    assert r.status in {"UNKNOWN", "PARTIAL"}, r.to_dict()
    assert r.to_dict().get("evidence_trace", {}).get("analysis_incomplete") is True
