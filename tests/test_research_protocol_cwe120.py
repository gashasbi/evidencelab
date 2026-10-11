from pathlib import Path
import json
import tempfile
from evidencelab.evaluator import compare_manifests, run_manifest
from evidencelab.matcher import Matcher
from evidencelab.parsers import parse_graph
from evidencelab.research_check import run_research_check
from evidencelab.sarif import validation_to_sarif
from evidencelab.spec import Pattern

ROOT = Path(__file__).resolve().parents[1]
FIXED = ROOT / "examples/cwe-121/families/fixed-write"
UNB = ROOT / "examples/cwe-121/families/unbounded-copy"


def test_partial_metadata_survives_canonical_parse_and_forces_unknown():
    g = parse_graph(UNB / "graphs/unbounded_unknown_partial_09.json")
    assert g.metadata["completeness"] == "partial"
    assert g.metadata["candidate_truncated"]
    r = Matcher(g).run(Pattern.load(UNB / "pattern.json"))
    assert r.status == "UNKNOWN"


def test_unbounded_unknown_corpus_has_no_overclaims():
    p = Pattern.load(UNB / "pattern.json")
    _, metrics, meta = run_manifest(UNB / "benchmark.json", p, reveal=False)
    d = metrics.to_dict()
    assert d["unknown_wrong"] == 0
    assert meta["overclaims"] == 0
    assert d["actual_unknown"] == d["expected_unknown"]


def test_research_check_cwe121_passes():
    p = ROOT / "profiles/research-grade-c-cpp-joern.json"
    r = run_research_check(ROOT / "examples/cwe-121", p, enforce_gates=True)
    assert r["status"] == "PASS", r
    assert r["family_count"] == 2


def test_sarif_export_is_2_1_0():
    g = parse_graph(ROOT / "examples/cwe-121/graphs/vulnerable.json")
    pat = Pattern.load(FIXED / "pattern.json")
    from evidencelab.matcher import Matcher

    m = Matcher(g).run(pat)
    report = {
        "pattern": {
            "id": pat.pattern_id,
            "cwe": pat.cwe,
            "name": pat.name,
            "description": pat.description,
        },
        "match": m.to_dict(),
        "status": m.status,
    }
    sarif = validation_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "EvidenceLab"


def test_public_hidden_exact_digest_overlap_is_rejected():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        graphs = root / "graphs"
        graphs.mkdir()
        gpath = graphs / "g.json"
        gpath.write_text(
            json.dumps({"nodes": [{"id": "1", "type": "X"}], "edges": []}),
            encoding="utf-8",
        )
        pub = root / "public.json"
        hid = root / "hidden.json"
        payload = {
            "manifest_id": "m",
            "cases": [
                {
                    "id": "p",
                    "graph": "graphs/g.json",
                    "expected": "MATCH",
                    "partition": "public",
                }
            ],
        }
        pub.write_text(json.dumps(payload), encoding="utf-8")
        payload["cases"][0] = {
            "id": "h",
            "graph": "graphs/g.json",
            "expected": "NO_MATCH",
            "partition": "hidden",
        }
        hid.write_text(json.dumps(payload), encoding="utf-8")
        r = compare_manifests(pub, hid)
        assert r["status"] == "FAIL"
        assert r["overlaps"]
