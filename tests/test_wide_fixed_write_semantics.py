from evidencelab.models import Edge, Graph, Node
from evidencelab.semantics import _argument_nodes, enrich_graph


def test_wide_fixed_write_uses_element_count():
    graph = Graph()
    call = Node(
        "call",
        "CALL",
        {"name": "wmemcpy", "code": "wmemcpy(dst, src, 12)"},
    )
    graph.add_node(call)

    enrich_graph(graph)

    derived = graph.nodes["call"].properties["derived"]
    assert derived["fixed_extent_write_like"] is True
    assert derived["wide_fixed_extent_write_like"] is True
    assert derived["write_extent_unit"] == "ELEMENTS"


def test_wide_array_capacity_is_separate_from_byte_capacity():
    graph = Graph()
    graph.add_node(
        Node(
            "wide",
            "LOCAL",
            {
                "name": "wide",
                "code": "wchar_t wide[12]",
                "typeFullName": "wchar_t[12]",
            },
        )
    )
    graph.add_node(
        Node(
            "bytes",
            "LOCAL",
            {
                "name": "bytes",
                "code": "char bytes[12]",
                "typeFullName": "char[12]",
            },
        )
    )

    enrich_graph(graph)

    wide = graph.nodes["wide"].properties["derived"]
    byte_array = graph.nodes["bytes"].properties["derived"]

    assert wide["element_count"] == 12
    assert wide["memory_capacity_elements"] == 12
    assert wide["capacity_unit"] == "ELEMENTS"
    assert wide["byte_capacity_known"] is False
    assert "memory_capacity" not in wide

    assert byte_array["element_count"] == 12
    assert byte_array["memory_capacity_elements"] == 12
    assert byte_array["capacity_unit"] == "BYTES"
    assert byte_array["byte_capacity_known"] is True
    assert byte_array["memory_capacity"] == 12


def test_argument_nodes_deduplicates_edges_to_same_node():
    graph = Graph()
    graph.add_node(Node("call", "CALL", {"name": "wmemcpy"}))
    graph.add_node(Node("dst", "IDENTIFIER", {"argumentIndex": 1}))
    graph.add_node(Node("src", "IDENTIFIER", {"argumentIndex": 2}))
    graph.add_node(Node("count", "LITERAL", {"argumentIndex": 3, "code": "12"}))

    graph.add_edge(Edge("call", "dst", "ARGUMENT"))
    graph.add_edge(Edge("call", "dst", "AST"))
    graph.add_edge(Edge("call", "src", "ARGUMENT"))
    graph.add_edge(Edge("call", "count", "ARGUMENT"))

    args = _argument_nodes(graph, "call")

    assert [node.id for node in args] == ["dst", "src", "count"]


def test_wide_fixed_write_functions_use_element_count():
    for name in ("wmemcpy", "wmemmove", "wcsncpy"):
        graph = Graph()
        graph.add_node(Node("call", "CALL", {"name": name, "code": f"{name}(dst, src, 12)"}))

        enrich_graph(graph)

        derived = graph.nodes["call"].properties["derived"]
        assert derived["fixed_extent_write_like"] is True
        assert derived["wide_fixed_extent_write_like"] is True
        assert derived["write_extent_unit"] == "ELEMENTS"


def test_incomplete_graph_does_not_infer_argument_index_from_edge_order():
    graph = Graph(metadata={"completeness": "partial", "parse_health": "OK"})
    graph.add_node(Node("call", "CALL", {"name": "wmemcpy"}))
    graph.add_node(Node("dst", "IDENTIFIER", {}))
    graph.add_edge(Edge("call", "dst", "ARGUMENT"))

    enrich_graph(graph)

    derived = graph.nodes["dst"].properties.get("derived", {})
    provenance = graph.nodes["dst"].properties.get("derived_provenance", {})
    assert "argument_index" not in derived
    assert "argument_role" not in derived
    assert provenance["argument_index"] == (
        "UNKNOWN:argument_index_inference_suppressed_on_incomplete_graph"
    )


def test_incomplete_graph_preserves_explicit_argument_index():
    graph = Graph(metadata={"completeness": "partial", "parse_health": "OK"})
    graph.add_node(Node("call", "CALL", {"name": "wmemcpy"}))
    graph.add_node(Node("dst", "IDENTIFIER", {}))
    graph.add_edge(
        Edge("call", "dst", "ARGUMENT", {"argumentIndex": 1})
    )

    enrich_graph(graph)

    derived = graph.nodes["dst"].properties["derived"]
    assert derived["argument_index"] == 1
    assert derived["argument_role"] == "destination"


def test_incomplete_graph_does_not_infer_subtraction_from_node_id_order():
    from evidencelab.semantics import node_value_range

    graph = Graph(
        metadata={"completeness": "partial", "parse_health": "OK"}
    )
    graph.add_node(
        Node("sub", "CALL", {"name": "<operator>.subtraction"})
    )
    graph.add_node(Node("z_left", "LITERAL", {"code": "10"}))
    graph.add_node(Node("a_right", "LITERAL", {"code": "3"}))

    graph.add_edge(Edge("sub", "z_left", "ARGUMENT"))
    graph.add_edge(Edge("sub", "a_right", "ARGUMENT"))

    enrich_graph(graph)

    # The graph does not establish which operand is first.
    assert "numeric_value" not in graph.nodes["sub"].properties.get("derived", {})
    assert node_value_range(graph, "sub") is None
