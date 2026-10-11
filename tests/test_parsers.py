from pathlib import Path
from evidencelab.parsers import parse_graph
from evidencelab.semantics import enrich_graph

ROOT = Path(__file__).resolve().parents[1]


def test_flatgraph_graphml_realistic():
    g = parse_graph(ROOT / "tests/fixtures/joern-flatgraph.graphml")
    assert g.metadata["parse_health"] == "OK"
    assert g.nodes["1"].type == "CALL" and g.nodes["1"].get("name") == "strcpy"
    # Joern GraphML declares CODE as a string; numeric meaning is represented
    # by the deterministic semantic layer rather than changing raw source text.
    assert g.nodes["3"].get("code") == "32"
    enrich_graph(g)
    assert g.nodes["3"].properties["derived"]["numeric_value"] == 32


def test_graphson():
    g = parse_graph(ROOT / "tests/fixtures/joern-graphson.json")
    assert g.nodes["1"].type == "CALL" and g.nodes["2"].get("code") == "64"


def test_dataflow_and_flow_json():
    g = parse_graph(ROOT / "tests/fixtures/joern-dataflow-slice.json")
    assert (
        g.metadata["format"] == "joern-dataflow-slice"
        and g.edges[0].type == "REACHING_DEF"
    )
    f = parse_graph(ROOT / "tests/fixtures/joern-flow-paths.json")
    assert len(f.nodes) == 3 and all(e.type == "DATA_FLOW" for e in f.edges)


def test_enrichment_extracts_array_length_and_numeric_literal():
    g = parse_graph(ROOT / "examples/cwe-121/graphs/vulnerable.json")
    enrich_graph(g)
    assert g.nodes["4"].properties["derived"]["is_array"] is True
    assert g.nodes["4"].properties["derived"]["length"] == 32
    assert g.nodes["5"].properties["derived"]["numeric_value"] == 64
