from pathlib import Path
from evidencelab.models import Graph, Node, Edge
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern

ROOT = Path(__file__).resolve().parents[1]


def _current_pattern(raw):
    """Give compact security-property fixtures the complete 1.0 contract."""
    unknown_policy = raw.get("unknown_policy", "unknown")
    raw.setdefault("family_id", "security-property-test")
    raw.setdefault(
        "evidence_contract",
        {
            "unknown_policy": unknown_policy,
            "counter_unknown_policy": raw.get("counter_unknown_policy", "block_match"),
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
        },
    )
    raw.setdefault(
        "semantic_contract",
        {
            "canonical_graph_required": True,
            "analyzer_independent": True,
        },
    )
    raw.setdefault("relevance_policy", {"minimum_sufficient_witness": True})
    raw.setdefault("path_budget", {"max_hops": 24})
    raw.setdefault(
        "provenance_policy",
        {
            "derived_facts_require_inputs": True,
            "artifact_hashes": True,
        },
    )
    return Pattern.from_dict(raw)


def test_witness_coherence():
    g = Graph()
    for n in [
        Node("s1", "PARAMETER", {"name": "a"}),
        Node("s2", "PARAMETER", {"name": "b"}),
        Node("k1", "CALL", {"name": "write"}),
        Node("k2", "CALL", {"name": "write"}),
        Node("t1", "LOCAL", {"name": "buf1", "typeFullName": "char[8]"}),
        Node("t2", "LOCAL", {"name": "buf2", "typeFullName": "char[8]"}),
    ]:
        g.add_node(n)
    g.add_edge(Edge("s1", "k1", "DATA_FLOW"))
    g.add_edge(Edge("s2", "k2", "DATA_FLOW"))
    g.add_edge(Edge("k1", "t1", "ARGUMENT"))
    g.add_edge(Edge("k2", "t2", "ARGUMENT"))
    # Pattern is intentionally small for a coherence check; no cross-pair should be constructed.
    p = _current_pattern(
        {
            "schema_version": "1.0",
            "pattern_id": "coh",
            "cwe": "CWE-999",
            "name": "coh",
            "version": "1.0.0",
            "language": "C/C++",
            "concepts": {
                "s": {"selectors": [{"type_any": ["PARAMETER"]}]},
                "k": {"selectors": [{"type_any": ["CALL"], "name_any": ["write"]}]},
                "t": {"selectors": [{"type_any": ["LOCAL"]}]},
            },
            "slots": [
                {"id": "s", "concept": "s"},
                {"id": "k", "concept": "k"},
                {"id": "t", "concept": "t"},
            ],
            "claims": [
                {"id": "c1", "kind": "node", "required": True, "slot": "s"},
                {"id": "c2", "kind": "node", "required": True, "slot": "k"},
                {"id": "c3", "kind": "node", "required": True, "slot": "t"},
                {
                    "id": "c4",
                    "kind": "path",
                    "required": True,
                    "source": "s",
                    "target": "k",
                    "edge_types": ["DATA_FLOW"],
                },
                {
                    "id": "c5",
                    "kind": "edge",
                    "required": True,
                    "source": "k",
                    "target": "t",
                    "edge_types": ["ARGUMENT"],
                },
            ],
            "witnesses": [
                {
                    "id": "w",
                    "slots": ["s", "k", "t"],
                    "claims": ["c1", "c2", "c3", "c4", "c5"],
                }
            ],
            "counter_evidence": [],
        }
    )
    r = Matcher(g).run(p)
    assert r.status == "MATCH"
    b = r.witnesses[0].bindings
    assert b["s"] == "s1" and b["k"] == "k1" and b["t"] == "t1"


def test_cardinality_upper_bound_is_unknown_on_incomplete_graph():
    from evidencelab.models import Graph, Node
    from evidencelab.spec import Pattern
    from evidencelab.matcher import Matcher

    g = Graph(
        nodes={"a": Node("a", "CALL", {"name": "foo"})},
        edges=[],
        metadata={"completeness": "partial", "parse_health": "OK"},
    )
    raw = {
        "schema_version": "1.0",
        "pattern_id": "cardinality-test",
        "cwe": "CWE-121",
        "name": "cardinality",
        "version": "1.0.0",
        "language": "C/C++",
        "concepts": {"x": {"selectors": [{"type_any": ["CALL"]}]}},
        "slots": [{"id": "x", "concept": "x"}],
        "claims": [{"id": "c1", "kind": "cardinality", "slot": "x", "max_count": 1}],
        "witnesses": [{"id": "w", "slots": ["x"], "claims": ["c1"]}],
        "provenance": [],
        "coverage": {},
    }
    r = Matcher(g).run(_current_pattern(raw))
    assert r.witnesses[0].claims[0].status == "UNKNOWN"


def test_relation_any_absence_is_disproved_on_complete_graph_and_unknown_on_incomplete():
    from evidencelab.models import Graph, Node, Edge
    from evidencelab.matcher import Matcher
    from evidencelab.spec import Pattern

    def pat():
        return _current_pattern(
            {
                "schema_version": "1.0",
                "pattern_id": "r",
                "cwe": "CWE-999",
                "name": "relation",
                "version": "1",
                "language": "C/C++",
                "concepts": {
                    "sink": {
                        "selectors": [{"type_any": ["CALL"], "name_any": ["sink"]}]
                    },
                    "guard": {
                        "selectors": [
                            {
                                "type_any": ["CONTROL_STRUCTURE"],
                                "properties": {"derived.guard_safe": True},
                            }
                        ]
                    },
                },
                "slots": [{"id": "sink", "concept": "sink"}],
                "claims": [
                    {"id": "c1", "kind": "node", "required": True, "slot": "sink"}
                ],
                "counter_evidence": [
                    {
                        "id": "x",
                        "kind": "relation_any",
                        "required": False,
                        "source_selector": {
                            "type_any": ["CONTROL_STRUCTURE"],
                            "properties": {"derived.guard_safe": True},
                        },
                        "target": "sink",
                        "relation": "DOMINANCE",
                        "max_hops": 1,
                    }
                ],
                "witnesses": [
                    {
                        "id": "w",
                        "slots": ["sink"],
                        "claims": ["c1"],
                        "counter_claims": ["x"],
                    }
                ],
                "unknown_policy": "unknown",
                "counter_unknown_policy": "block_match",
            }
        )

    g = Graph(
        nodes={"s": Node("s", "CALL", {"name": "sink"})},
        edges=[],
        metadata={"schema_version": "1.0", "format": "json"},
    )
    m = Matcher(g).run(pat())
    assert m.status == "MATCH"
    assert m.witnesses[0].counter_evidence[0].status == "DISPROVEN"
    g2 = Graph(
        nodes={"s": Node("s", "CALL", {"name": "sink"})},
        edges=[],
        metadata={
            "schema_version": "1.0",
            "format": "json",
            "completeness": "partial",
            "parse_health": "DEGRADED",
            "analysis_truncated": True,
        },
    )
    m2 = Matcher(g2).run(pat())
    assert m2.status == "UNKNOWN"


def test_parent_method_relation_uses_structural_parent_from_joern():
    from pathlib import Path
    from tempfile import TemporaryDirectory
    import subprocess
    from evidencelab.parsers import parse_graph
    from evidencelab.spec import Pattern

    with TemporaryDirectory() as td:
        out = Path(td) / "merged.json"
        subprocess.run(
            [
                "python3",
                "-m",
                "evidencelab",
                "merge",
                "--graph",
                str(ROOT / "examples/cwe-120/joern-fixture/p03-export.xml"),
                "--graph",
                str(ROOT / "examples/cwe-120/joern-fixture/p03-flow.json"),
                "--out",
                str(out),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        g = parse_graph(out)
        p = Pattern.load(
            ROOT / "examples/cwe-120/families/fixed-extent-overflow/pattern.json"
        )
        m = Matcher(g).run(p)
        assert m.status == "MATCH"
