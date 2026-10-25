from pathlib import Path
from evidencelab.parsers import parse_graph
from evidencelab.semantics import enrich_graph

ROOT = Path(__file__).resolve().parents[1]


def test_flatgraph_graphml_realistic():
    g = parse_graph(ROOT / "tests/fixtures/joern-flatgraph.graphml")
    assert g.metadata["parse_health"] == "OK"
    assert g.nodes["1"].type == "CALL" and g.nodes["1"].get("name") == "strcpy"

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


def test_generic_json_preserves_declared_degraded_parse_health(tmp_path):
    import json
    from evidencelab.parsers import parse_graph

    path = tmp_path / "declared-degraded.json"
    path.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "n1", "type": "CALL", "properties": {"name": "sprintf"}}
                ],
                "edges": [],
                "metadata": {
                    "parse_health": "DEGRADED",
                    "completeness": "partial",
                },
            }
        ),
        encoding="utf-8",
    )

    graph = parse_graph(path)

    assert graph.metadata["parse_health"] == "DEGRADED"
    assert graph.metadata["declared_metadata"]["parse_health"] == "DEGRADED"


def test_generic_json_declared_ok_cannot_hide_structural_degradation(tmp_path):
    import json
    from evidencelab.parsers import parse_graph

    path = tmp_path / "structurally-degraded.json"
    path.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "n1", "type": "CALL", "properties": {"name": "sprintf"}}
                ],
                "edges": [
                    {
                        "id": "e1",
                        "source": "n1",
                        "target": "missing-node",
                        "type": "AST",
                    }
                ],
                "metadata": {
                    "parse_health": "OK",
                    "completeness": "declared",
                },
            }
        ),
        encoding="utf-8",
    )

    graph = parse_graph(path)

    assert graph.metadata["parse_health"] == "DEGRADED"
    assert graph.metadata["declared_metadata"]["parse_health"] == "OK"
