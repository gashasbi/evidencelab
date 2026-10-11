from evidencelab.models import Graph, Node
from evidencelab.spec import Pattern
from evidencelab.witness_replay import WitnessReplay


def _current_pattern(raw):
    """Populate the required 1.0 contract for this focused replay fixture."""
    raw.setdefault("family_id", "witness-replay-test")
    raw.setdefault(
        "evidence_contract",
        {
            "unknown_policy": "unknown",
            "counter_unknown_policy": "block_match",
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
        },
    )
    raw.setdefault(
        "semantic_contract",
        {"canonical_graph_required": True, "analyzer_independent": True},
    )
    raw.setdefault("relevance_policy", {"minimum_sufficient_witness": True})
    raw.setdefault("path_budget", {"max_hops": 24})
    raw.setdefault(
        "provenance_policy",
        {"derived_facts_require_inputs": True, "artifact_hashes": True},
    )
    return Pattern.from_dict(raw)


def _graph():
    g = Graph()
    g.add_node(
        Node(
            "extent",
            "IDENTIFIER",
            properties={
                "derived": {"range": {"lower": 48, "upper": 48, "proof": "LITERAL"}}
            },
        )
    )
    g.add_node(
        Node(
            "target",
            "LOCAL",
            properties={"memory_capacity": 32, "derived": {"memory_capacity": 32}},
        )
    )
    return g


def _pattern():
    return _current_pattern(
        {
            "schema_version": "1.0",
            "pattern_id": "range-replay-test",
            "cwe": "CWE-120",
            "name": "range replay",
            "version": "1.0.0",
            "language": "C/C++",
            "concepts": {
                "extent": {"selectors": [{"type_any": ["LITERAL"]}]},
                "target": {"selectors": [{"type_any": ["LOCAL"]}]},
            },
            "slots": [
                {"id": "extent", "concept": "extent"},
                {"id": "target", "concept": "target"},
            ],
            "claims": [
                {
                    "id": "c",
                    "kind": "range_compare",
                    "required": True,
                    "left": {"slot": "extent", "property": "derived.range"},
                    "right": {"slot": "target", "property": "derived.memory_capacity"},
                    "operator": ">",
                }
            ],
            "counter_evidence": [],
            "witnesses": [{"id": "w", "slots": ["extent", "target"], "claims": ["c"]}],
        }
    )


def test_fixed_binding_range_replay_proves_same_relation():
    replay = WitnessReplay(_graph(), _pattern())
    result = replay.claim(
        _pattern().claims[0], {"extent": "extent", "target": "target"}
    )
    assert result["status"] == "PROVEN"
    assert result["matches"][0]["left"]["lower"] == 48
    assert result["matches"][0]["right"]["lower"] == 32
