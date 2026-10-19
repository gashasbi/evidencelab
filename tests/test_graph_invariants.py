from evidencelab.models import Graph, Node, Edge
from evidencelab.canonical import canonicalize_graph, canonical_node_type, canonical_edge_types
from evidencelab.semantics import enrich_graph

def _sample(order=("a","b","c")):
    g = Graph(metadata={"completeness":"full_export","parse_health":"OK"})
    data = {
        "a": Node("a","METHOD_PARAMETER_IN",{"name":"input","code":"char *input"}),
        "b": Node("b","CALL",{"name":"memcpy","code":"memcpy(dst, input, 16)"}),
        "c": Node("c","LOCAL",{"name":"dst","typeFullName":"char[8]"}),
    }
    for k in order: g.add_node(data[k])
    g.add_edge(Edge("a","b","REACHING_DEF"))
    g.add_edge(Edge("b","c","ARGUMENT",{"argumentIndex":1}))
    return g

def test_node_aliases_are_stable():
    assert canonical_node_type("METHOD_PARAMETER_IN") == "PARAMETER"
    assert canonical_node_type("METHOD_PARAMETER_OUT") == "PARAMETER"
    assert canonical_node_type("CALL") == "CALL"

def test_edge_aliases_are_stable():
    assert canonical_edge_types("REACHING_DEF") == ["DATA_FLOW"]
    assert canonical_edge_types("REF") == ["REFERENCE"]

def test_canonical_graph_preserves_identity_and_semantic_edges():
    g = canonicalize_graph(_sample())
    assert set(g.nodes) == {"a","b","c"}
    assert any(
        e.type == "REACHING_DEF"
        and e.properties.get("canonical_edge_type") == "DATA_FLOW"
        for e in g.edges
    )
    assert any(e.type == "ARGUMENT" for e in g.edges)

def test_graph_digest_ignores_node_insertion_order():
    assert _sample(("a","b","c")).digest() == _sample(("c","a","b")).digest()

def test_unknown_external_function_is_not_falsely_classified_as_unbounded():
    g = Graph(metadata={"completeness":"full_export","parse_health":"OK"})
    g.add_node(Node("external","CALL",{"name":"copy_with_contract",
        "code":"copy_with_contract(dst, input, claimed_capacity)",
        "methodFullName":"copy_with_contract"}))
    enrich_graph(g)
    d = g.nodes["external"].properties.get("derived", {})
    assert d.get("unbounded_write_like") is not True

def test_known_memcpy_is_fixed_extent_not_unbounded():
    g = Graph()
    g.add_node(Node("copy","CALL",{"name":"memcpy","code":"memcpy(dst, src, 8)"}))
    enrich_graph(g)
    d = g.nodes["copy"].properties.get("derived", {})
    assert d.get("memory_write_like") is True
    assert d.get("fixed_extent_write_like") is True
    assert d.get("unbounded_write_like") is False

def test_canonicalization_is_repeatable():
    first = canonicalize_graph(_sample())
    second = canonicalize_graph(first)
    assert first.digest() == second.digest()
def test_matcher_does_not_mutate_caller_graph():
    original = _sample()
    before = original.digest()
    from evidencelab.matcher import Matcher
    Matcher(original)
    assert original.digest() == before

def test_canonicalization_does_not_drop_unknown_node_types():
    g = Graph()
    g.add_node(Node("future", "FUTURE_ANALYZER_NODE", {"name": "keep-me"}))
    canonical = canonicalize_graph(g)
    assert "future" in canonical.nodes
    assert canonical.nodes["future"].type == "FUTURE_ANALYZER_NODE"
