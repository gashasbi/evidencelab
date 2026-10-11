from pathlib import Path
from evidencelab.parsers import parse_graph
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern
from evidencelab.audit import audit_pattern
from evidencelab.evaluator import run_manifest

ROOT = Path(__file__).resolve().parents[1]
PAT = ROOT / "examples/cwe-121/evidence-pattern.json"
BENCH = ROOT / "examples/cwe-121/benchmark.json"


def test_example_pattern_audit_passes():
    p = Pattern.load(PAT)
    fs = audit_pattern(
        p,
        {
            "min_required_claims": 6,
            "min_concepts": 3,
            "min_required_claim_kinds": 3,
            "min_provenance": 2,
        },
    )
    assert not [f for f in fs if f.severity == "ERROR"], fs


def test_definite_overflow_matches():
    p = Pattern.load(PAT)
    g = parse_graph(ROOT / "examples/cwe-121/graphs/vulnerable.json")
    r = Matcher(g).run(p)
    assert r.status == "MATCH", r.to_dict()
    w = r.witnesses[0]
    assert w.bindings["target"] == "4" and w.bindings["extent"] == "5"


def test_safe_extent_does_not_match():
    p = Pattern.load(PAT)
    g = parse_graph(ROOT / "examples/cwe-121/graphs/safe.json")
    r = Matcher(g).run(p)
    assert r.status != "MATCH", r.to_dict()


def test_benchmark_metrics():
    p = Pattern.load(PAT)
    cases, m, meta = run_manifest(BENCH, p)
    d = m.to_dict()
    assert d["tp"] == 1 and d["tn"] == 1 and d["fp"] == 0 and d["fn"] == 0
    assert (
        d["precision"] == 1.0
        and d["recall"] == 1.0
        and meta["partitions"]["public"] == 2
    )
