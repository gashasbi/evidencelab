from pathlib import Path
import json, tempfile
from evidencelab.evidence import EvidenceLedger, EvidenceItem, EvidenceRef, ProofState
from evidencelab.project import init_research_project, append_experiment
from evidencelab.research_package import audit_research_package
from evidencelab.corpus import split_manifest, source_inventory
from evidencelab.tef import validate_tef, to_evidencelab_notes
from evidencelab.matcher import Matcher
from evidencelab.parsers import parse_graph
from evidencelab.spec import Pattern

ROOT = Path(__file__).resolve().parents[1]


def test_evidence_ledger_never_upgrades_unknown():
    l = EvidenceLedger()
    l.add(
        EvidenceItem(
            "e1", "OBSERVATION", "UNKNOWN", "x", provenance=[EvidenceRef("graph", "1")]
        )
    )
    assert l.by_state(ProofState.PROVEN) == []
    assert l.to_dict()["items"][0]["state"] == "UNKNOWN"


def test_match_result_contains_ledger():
    g = parse_graph(ROOT / "examples/cwe-121/graphs/vulnerable.json")
    p = Pattern.load(ROOT / "examples/cwe-121/evidence-pattern.json")
    r = Matcher(g).run(p)
    assert "items" in r.ledger
    assert any(x["id"].startswith("CLAIM:") for x in r.ledger["items"])


def test_research_project_scaffold_is_complete():
    with tempfile.TemporaryDirectory() as td:
        root = init_research_project("CWE-120", Path(td) / "r")
        for rel in (
            "task.json",
            "research-plan.md",
            "family-template.json",
            "evidence/pattern.json",
            "benchmarks/public/benchmark.json",
            "benchmarks/hidden/benchmark.json",
            "experiments/experiment-log.jsonl",
            "notes/evidence-decisions.md",
            "queries/README.md",
            "submission.json",
        ):
            assert (root / rel).exists(), rel
        assert audit_research_package(root)["status"] == "SCAFFOLD"
        append_experiment(
            root,
            {
                "experiment_id": "E1",
                "hypothesis": "h",
                "tool": "Joern",
                "command": "joern --help",
                "result": "pass",
            },
        )
        assert (root / "experiments/experiment-log.jsonl").read_text().strip()


def test_benchmark_split_is_deterministic_and_partitions():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        g = root / "g.json"
        g.write_text(
            json.dumps({"nodes": [{"id": "1", "type": "X"}], "edges": []}),
            encoding="utf-8",
        )
        m = root / "m.json"
        m.write_text(
            json.dumps(
                {
                    "manifest_id": "m",
                    "cases": [
                        {"id": str(i), "graph": "g.json", "expected": "NO_MATCH"}
                        for i in range(10)
                    ],
                }
            ),
            encoding="utf-8",
        )
        a = split_manifest(m, root / "pub.json", root / "hid.json", 0.3, "s")
        b = split_manifest(m, root / "pub2.json", root / "hid2.json", 0.3, "s")
        assert a["public"] == b["public"] and a["hidden"] == b["hidden"]
        assert a["public"] + a["hidden"] == 10


def test_tef_bridge_validates_and_normalizes():
    raw = {
        "defect": {
            "product": "p",
            "vendor": "v",
            "type": "server",
            "cwe": 120,
            "versions": ["1.0"],
            "presence": "static_artefact",
        },
        "evidence": [{"title": "x", "given": ["g"], "when": ["w"], "then": ["t"]}],
    }
    assert validate_tef(raw) == []
    notes = to_evidencelab_notes(raw)
    assert (
        notes["format"] == "evidencelab-tef-bridge"
        and notes["scenarios"][0]["title"] == "x"
    )


def test_source_inventory_empty_tree():
    with tempfile.TemporaryDirectory() as td:
        assert source_inventory(td) == []
