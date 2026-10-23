from evidencelab.models import Edge, Graph, Node
from evidencelab.semantics import same_object_call_binding_proof


def make_call_graph():
    graph = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})

    nodes = [
        Node("wrapper_method", "METHOD", {}),
        Node("helper_method", "METHOD", {}),
        Node(
            "call",
            "CALL",
            {"derived": {"parent_method_node": "wrapper_method"}},
        ),
        Node(
            "actual",
            "IDENTIFIER",
            {
                "derived": {
                    "argument_index": 1,
                    "parent_method_node": "wrapper_method",
                },
                "derived_provenance": {"argument_index": "DERIVED:argument_position"},
            },
        ),
        Node(
            "target",
            "LOCAL",
            {
                "derived": {
                    "parent_method_node": "wrapper_method",
                    "storage_duration": "AUTOMATIC",
                    "is_array": True,
                }
            },
        ),
        Node(
            "destination",
            "IDENTIFIER",
            {"derived": {"parent_method_node": "helper_method"}},
        ),
        Node(
            "parameter",
            "METHOD_PARAMETER_IN",
            {
                "INDEX": 1,
                "derived": {"parent_method_node": "helper_method"},
            },
        ),
    ]

    for node in nodes:
        graph.add_node(node)

    edges = [
        Edge("destination", "parameter", "REF"),
        Edge("call", "helper_method", "CALL"),
        Edge("call", "actual", "ARGUMENT"),
        Edge("actual", "target", "REF"),
    ]
    for edge in edges:
        graph.add_edge(edge)

    return graph


def test_call_binding_proves_parameter_resolves_to_target():
    graph = make_call_graph()
    proof = same_object_call_binding_proof(
        graph, graph.nodes["destination"], graph.nodes["target"]
    )

    assert proof is not None
    assert proof["proof"] == "CALL_ARGUMENT_PARAMETER_REF"
    assert proof["parameter_index"] == 1
    assert proof["argument_index"] == 1
    assert proof["target_object"] == "target"


def test_call_binding_rejects_different_argument_index():
    graph = make_call_graph()
    graph.nodes["actual"].properties["derived"]["argument_index"] = 2

    assert (
        same_object_call_binding_proof(
            graph, graph.nodes["destination"], graph.nodes["target"]
        )
        is None
    )


def test_call_binding_rejects_target_from_another_caller():
    graph = make_call_graph()
    graph.nodes["target"].properties["derived"]["parent_method_node"] = (
        "different_method"
    )
    graph.add_node(Node("different_method", "METHOD", {}))

    assert (
        same_object_call_binding_proof(
            graph, graph.nodes["destination"], graph.nodes["target"]
        )
        is None
    )


def test_call_binding_rejects_unknown_argument_index():
    graph = make_call_graph()
    del graph.nodes["actual"].properties["derived"]["argument_index"]
    graph.nodes["actual"].properties["derived_provenance"]["argument_index"] = (
        "UNKNOWN:INCOMPLETE_ARGUMENTS"
    )

    assert (
        same_object_call_binding_proof(
            graph, graph.nodes["destination"], graph.nodes["target"]
        )
        is None
    )


def test_edge_claim_uses_call_binding_only_when_enabled():
    from evidencelab.matcher import Matcher
    from evidencelab.spec import Claim

    graph = make_call_graph()
    binding = {"destination": "destination", "target": "target"}

    claim = Claim(
        id="C8",
        kind="edge",
        required=True,
        description="destination resolves to target",
        source="destination",
        target="target",
        edge_types=["REF"],
        direction="either",
        allow_call_binding=True,
    )

    result = Matcher(graph)._claim_with_binding(claim, binding, {})
    assert result.status == "PROVEN"

    claim.allow_call_binding = False
    result = Matcher(graph)._claim_with_binding(claim, binding, {})
    assert result.status == "DISPROVEN"
