from pathlib import Path
from evidencelab.models import Graph, Node
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern
from evidencelab.witness_replay import WitnessReplay


def _pattern():
    return Pattern.from_dict(
        {
            "schema_version": "1.0",
            "pattern_id": "qa-report",
            "cwe": "CWE-999",
            "name": "report consistency",
            "version": "1.0",
            "language": "C/C++",
            "family_id": "qa-report",
            "concepts": {
                "sink": {"selectors": [{"type_any": ["CALL"], "name_any": ["sink"]}]}
            },
            "slots": [{"id": "sink", "concept": "sink"}],
            "claims": [{"id": "C1", "kind": "node", "required": True, "slot": "sink"}],
            "counter_evidence": [],
            "witnesses": [
                {"id": "W1", "slots": ["sink"], "claims": ["C1"], "required": True}
            ],
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


def test_match_result_trace_and_witness_agree():
    g = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    g.add_node(Node("sink", "CALL", {"name": "sink"}))
    data = Matcher(g).run(_pattern()).to_dict()
    assert data["status"] == "MATCH"
    assert data["witnesses"]
    assert any(w.get("status") == "MATCH" for w in data["witnesses"])
    assert data.get("evidence_trace", {}).get("graph_digest")


def test_witness_replay_accepts_untampered_match():
    g = Graph(metadata={"completeness": "full_export", "parse_health": "OK"})
    g.add_node(Node("sink", "CALL", {"name": "sink"}))
    p = _pattern()
    report = Matcher(g).run(p).to_dict()
    replay = WitnessReplay(g, p).validate(report)
    assert replay.get("status") == "PASS", replay


def test_documentation_does_not_conflate_no_match_with_safety_proof(repo_root):
    content = []
    for item in (repo_root / "README.md", repo_root / "docs"):
        if item.is_file():
            content.append(item.read_text(encoding="utf-8", errors="replace").lower())
        elif item.is_dir():
            content.extend(
                p.read_text(encoding="utf-8", errors="replace").lower()
                for p in item.rglob("*.md")
                if p.is_file()
            )
    joined = "\\n".join(content)
    assert "no_match" in joined
    assert (
        ("not" in joined and "proof" in joined)
        or "does not prove" in joined
        or "not a proof" in joined
    )
