from pathlib import Path
import json
from evidencelab.parsers import parse_graph
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern
from evidencelab.submission import create_submission_manifest, validate_submission
from evidencelab.audit import audit_pattern

ROOT = Path(__file__).resolve().parents[1]
PAT = ROOT / "examples/cwe-121/evidence-pattern.json"


def test_graphml_preserves_code_strings_and_labels():
    g = parse_graph(ROOT / "tests/fixtures/joern-realistic.graphml")
    assert g.metadata["parse_health"] == "OK"
    assert g.nodes["1"].type == "CALL"
    assert g.nodes["1"].get("CODE") == "memcpy(buffer, input, 64)"
    assert isinstance(g.nodes["3"].get("CODE"), str)
    assert g.nodes["3"].get("CODE") == "64"
    assert g.edges[0].type == "ARGUMENT"


def test_partial_graph_cannot_prove_absence():
    raw = {
        "$type": "DataFlowSlice",
        "nodes": [{"id": 1, "label": "CALL", "code": "foo()"}],
        "edges": [],
    }
    p = ROOT / "/tmp-do-not-exist" if False else None
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "slice.json"
        f.write_text(json.dumps(raw))
        g = parse_graph(f)
        pattern = Pattern.from_dict(
            {
                "schema_version": "1.0",
                "pattern_id": "abs",
                "cwe": "CWE-999",
                "name": "absence",
                "version": "1.0.0",
                "language": "C/C++",
                "family_id": "absence-family",
                "concepts": {
                    "x": {
                        "selectors": [
                            {"type_any": ["CALL"], "name_any": ["not_present"]}
                        ]
                    }
                },
                "slots": [],
                "claims": [
                    {
                        "id": "x",
                        "kind": "node_absence",
                        "required": True,
                        "selector": {"type_any": ["CALL"], "name_any": ["not_present"]},
                    }
                ],
                "counter_evidence": [],
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
        r = Matcher(g).run(pattern)
        assert r.status != "MATCH"


def test_example_pattern_requires_research_grade_features():
    p = Pattern.load(PAT)
    fs = audit_pattern(
        p,
        {
            "min_required_claims": 8,
            "min_concepts": 5,
            "min_required_claim_kinds": 4,
            "min_provenance": 3,
            "require_relation_edge_types": True,
            "signature_only_is_error": True,
            "min_coverage_dimensions": 5,
        },
    )
    assert not [x for x in fs if x.severity == "ERROR"], fs


def test_submission_roundtrip():
    import tempfile, shutil

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "submission"
        root.mkdir()
        (root / "evidence").mkdir()
        (root / "graphs").mkdir()
        (root / "benchmarks").mkdir()
        shutil.copy2(PAT, root / "evidence/pattern.json")
        shutil.copy2(
            ROOT / "examples/cwe-121/graphs/vulnerable.json", root / "graphs/v.json"
        )
        (root / "benchmarks/manifest.json").write_text(
            json.dumps(
                {
                    "manifest_id": "pub",
                    "cases": [
                        {
                            "id": "v",
                            "graph": "../graphs/v.json",
                            "expected": "MATCH",
                            "partition": "public",
                            "tags": ["positive", "direct", "fixed_extent"],
                        }
                    ],
                },
                indent=2,
            )
        )
        create_submission_manifest(
            root,
            "CWE-121",
            "evidence/pattern.json",
            ["graphs/v.json"],
            "benchmarks/manifest.json",
        )
        s = json.loads((root / "submission.json").read_text())
        assert s["toolchain"]["joern_version"] is None or isinstance(
            s["toolchain"]["joern_version"], str
        )
        out = validate_submission(root)
        assert out["file_validation"]["status"] == "PASS"
        assert out["status"] == "PASS", out


def test_semantic_dataflow_relation_matches_joern_reaching_def():
    from evidencelab.models import Graph, Node, Edge

    raw = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    raw.add_node(
        Node(
            "s",
            "METHOD_PARAMETER_IN",
            {"code": "char *input", "name": "input", "typeFullName": "char*"},
        )
    )
    raw.add_node(
        Node(
            "k",
            "CALL",
            {
                "name": "memcpy",
                "code": "memcpy(buffer,input,64)",
                "methodFullName": "memcpy",
            },
        )
    )
    raw.add_node(
        Node(
            "d",
            "IDENTIFIER",
            {"name": "buffer", "code": "buffer", "typeFullName": "char[32]"},
        )
    )
    raw.add_node(
        Node(
            "t",
            "LOCAL",
            {"name": "buffer", "code": "char buffer[32]", "typeFullName": "char[32]"},
        )
    )
    raw.add_node(
        Node("e", "LITERAL", {"name": "64", "code": "64", "typeFullName": "int"})
    )
    raw.add_edge(Edge("s", "d", "REACHING_DEF"))
    raw.add_edge(Edge("k", "d", "ARGUMENT"))
    raw.add_edge(Edge("d", "t", "REF"))
    raw.add_edge(Edge("k", "e", "ARGUMENT"))
    p = Pattern.load(ROOT / "examples/cwe-121/evidence-pattern.json")
    result = Matcher(raw).run(p)
    assert result.status == "MATCH", result.to_dict()
