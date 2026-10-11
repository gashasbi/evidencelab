from pathlib import Path
import json
from evidencelab.spec import Pattern
from evidencelab.matcher import Matcher
from evidencelab.parsers import parse_graph
from evidencelab.audit import audit_pattern
from evidencelab.evaluator import run_manifest, audit_benchmark_manifest

ROOT = Path(__file__).resolve().parents[1]
FIXED = ROOT / "examples/cwe-121/families/fixed-write"
UNB = ROOT / "examples/cwe-121/families/unbounded-copy"
GR = ROOT / "examples/cwe-121/corpus/graphs"


def load_graph(name):
    return parse_graph(GR / f"{name}.json")


def test_fixed_positive_matches():
    p = Pattern.load(FIXED / "pattern.json")
    m = Matcher(load_graph("fixed_pos_01")).run(p)
    assert m.status == "MATCH"
    w = m.witnesses[0]
    assert w.status == "MATCH"
    assert any(c.claim_id == "C12" and c.status == "PROVEN" for c in w.claims)


def test_fixed_safe_extent_does_not_match():
    p = Pattern.load(FIXED / "pattern.json")
    m = Matcher(load_graph("fixed_neg_bound_01")).run(p)
    assert m.status == "NO_MATCH"


def test_fixed_unknown_extent_is_not_promoted():
    p = Pattern.load(FIXED / "pattern.json")
    m = Matcher(load_graph("fixed_unknown_extent_01")).run(p)
    assert m.status in {"NO_MATCH", "PARTIAL", "UNKNOWN"}
    assert "matching_witnesses" in m.evidence_trace
    assert "unknown_counter_evidence" in m.evidence_trace


def test_semantic_relation_maps_reaching_def():
    p = Pattern.load(FIXED / "pattern.json")
    m = Matcher(load_graph("fixed_pos_01")).run(p)
    w = m.witnesses[0]
    c = next(x for x in w.claims if x.claim_id == "C7")
    assert c.status == "PROVEN"
    assert c.matches and c.matches[0]["path"][0] == "s"


def test_counter_evidence_is_not_rendered_as_positive_failure():
    p = Pattern.load(FIXED / "pattern.json")
    m = Matcher(load_graph("fixed_pos_01")).run(p)
    w = m.witnesses[0]
    x = next(c for c in w.counter_evidence if c.claim_id == "X1")
    assert x.status == "DISPROVEN"
    assert m.status == "MATCH"


def test_explicit_derived_storage_fact_is_preserved():
    g = load_graph("fixed_neg_static_01")
    from evidencelab.semantics import enrich_graph

    enrich_graph(g)
    assert g.nodes["t"].properties["derived"]["storage_duration"] == "STATIC_LOCAL"


def test_static_target_is_negative():
    p = Pattern.load(FIXED / "pattern.json")
    assert Matcher(load_graph("fixed_neg_static_01")).run(p).status == "NO_MATCH"


def test_heap_target_is_negative():
    p = Pattern.load(FIXED / "pattern.json")
    assert Matcher(load_graph("fixed_neg_heap_01")).run(p).status == "NO_MATCH"


def test_missing_flow_is_negative_on_complete_graph():
    p = Pattern.load(FIXED / "pattern.json")
    assert Matcher(load_graph("fixed_neg_noflow_01")).run(p).status == "NO_MATCH"


def test_unbounded_family_matches_strcpy():
    p = Pattern.load(UNB / "pattern.json")
    assert Matcher(load_graph("unbounded_pos_strcpy")).run(p).status == "MATCH"


def test_unbounded_family_matches_other_sinks():
    p = Pattern.load(UNB / "pattern.json")
    for name in (
        "unbounded_pos_strcat",
        "unbounded_pos_wcscpy",
        "unbounded_pos_wcscat",
    ):
        assert Matcher(load_graph(name)).run(p).status == "MATCH"


def test_audit_passes_for_both_families():
    profile = json.loads(
        (ROOT / "profiles/research-grade-c-cpp-joern.json").read_text()
    )
    for path in (FIXED / "pattern.json", UNB / "pattern.json"):
        p = Pattern.load(path)
        findings = audit_pattern(p, profile["audit"])
        assert not [f for f in findings if f.severity == "ERROR"], [
            f.to_dict() for f in findings
        ]


def test_benchmark_has_orthogonal_dimensions():
    p = Pattern.load(FIXED / "pattern.json")
    r = audit_benchmark_manifest(FIXED / "benchmark.json", p, required_dimensions=set())
    assert r["status"] == "PASS", r


def test_unbounded_benchmark_is_auditable():
    p = Pattern.load(UNB / "pattern.json")
    r = audit_benchmark_manifest(UNB / "benchmark.json", p, required_dimensions=set())
    assert r["status"] == "PASS", r


def test_benchmark_metrics_real_corpus():
    p = Pattern.load(FIXED / "pattern.json")
    cases, metrics, meta = run_manifest(FIXED / "benchmark.json", p)
    assert metrics.total >= 40
    assert metrics.tp >= 10
    assert metrics.tn >= 10
    md = metrics.to_dict()
    assert md["precision"] is not None
    assert md["recall"] is not None
    assert md["false_positive_rate"] is not None


def test_cwe120_all_families_audit_and_benchmark():
    root = ROOT / "examples/cwe-120/families"
    profile = json.loads(
        (ROOT / "profiles/research-grade-c-cpp-joern.json").read_text()
    )
    from evidencelab.spec import Pattern

    for family in sorted(root.iterdir()):
        p = Pattern.load(family / "pattern.json")
        findings = audit_pattern(p, profile["audit"])
        assert not [f for f in findings if f.severity == "ERROR"], [
            f.to_dict() for f in findings
        ]
        result = audit_benchmark_manifest(family / "benchmark.json", p)
        assert result["status"] == "PASS", result
        assert result["unique_graphs"] == result["case_count"]
        cases, metrics, meta = run_manifest(family / "benchmark.json", p)
        md = metrics.to_dict()
        assert md["tp"] >= 18 and md["tn"] >= 18 and md["expected_unknown"] >= 8
        assert md["precision"] >= 0.92 and md["recall"] >= 0.88 and md["f1"] >= 0.90
        assert md["false_positive_rate"] <= 0.08
        assert md["overclaims"] == 0


def test_cwe120_range_unknown_is_not_promoted():
    from evidencelab.spec import Pattern

    p = Pattern.load(
        ROOT / "examples/cwe-120/families/symbolic-range-overflow/pattern.json"
    )
    from evidencelab.parsers import parse_graph

    g = parse_graph(
        ROOT
        / "examples/cwe-120/families/symbolic-range-overflow/graphs/unknown_03.json"
    )
    from evidencelab.matcher import Matcher

    m = Matcher(g).run(p)
    assert m.status == "UNKNOWN"
