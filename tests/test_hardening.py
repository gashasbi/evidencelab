import json, os
from pathlib import Path
from types import SimpleNamespace

from evidencelab.evaluator import classify, compare_manifests
from evidencelab.contract import research_tree_inventory
from evidencelab.splits import split_benchmark
from evidencelab.matcher import Matcher
from evidencelab.spec import Pattern
from evidencelab.parsers import parse_graph

ROOT = Path(__file__).resolve().parents[1]


def test_unknown_no_match_is_not_safety_overclaim():
    result = classify("NO_MATCH", "UNKNOWN")
    assert result[8] == 0 and result[9] == 0


def test_public_hidden_overlap_detects_normalized_source_hash(tmp_path):
    g = tmp_path / "g.json"
    g.write_text(json.dumps({"schema_version": "1.0", "nodes": [], "edges": []}))
    pub = tmp_path / "pub.json"
    hid = tmp_path / "hid.json"
    base = {"graph": "g.json", "normalized_source_hash": "same", "source_sha256": "sha"}
    pub.write_text(json.dumps({"cases": [dict(base, id="p", expected="MATCH")]}))
    hid.write_text(json.dumps({"cases": [dict(base, id="h", expected="UNKNOWN")]}))
    r = compare_manifests(pub, hid)
    assert r["status"] == "FAIL"
    assert r["normalized_source_overlaps"]


def test_repository_split_keeps_counterpart_and_pair_together(tmp_path):
    g = tmp_path / "g.json"
    g.write_text(json.dumps({"schema_version": "1.0", "nodes": [], "edges": []}))
    cases = []
    for cid, repo, pair in [
        ("a", "r1", "p1"),
        ("b", "r2", "p1"),
        ("c", "r3", None),
        ("d", "r4", None),
        ("e", "r5", None),
        ("f", "r6", None),
    ]:
        x = {
            "id": cid,
            "expected": "MATCH",
            "graph": "g.json",
            "dataset": {"repository": repo},
        }
        if pair:
            x["pair_id"] = pair
        cases.append(x)
    m = tmp_path / "benchmark.json"
    m.write_text(json.dumps({"schema_version": "1.0", "cases": cases}))
    out = tmp_path / "split"
    r = split_benchmark(
        m, out, "repository", train=0.5, validation=0.25, test=0.25, seed="x"
    )
    assert r["status"] == "PASS"
    parts = {}
    for name in ("train", "validation", "test"):
        data = json.loads((out / f"{name}.json").read_text())
        for c in data["cases"]:
            parts[c["id"]] = name
    assert parts["a"] == parts["b"]


def test_research_inventory_rejects_external_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = root / "link.txt"
    link.symlink_to(outside)
    try:
        research_tree_inventory(root)
    except ValueError as exc:
        assert "outside root" in str(exc)
    else:
        raise AssertionError("external symlink was accepted")


def test_fixed_write_requires_byte_capacity_not_element_count():
    pattern = json.loads(
        (ROOT / "examples/cwe-121/families/fixed-write/pattern.json").read_text()
    )
    c12 = next(c for c in pattern["claims"] if c["id"] == "C12")
    assert c12["right"] == {"slot": "target", "property": "derived.memory_capacity"}
    assert any(
        c.get("id") == "C18"
        and c.get("equals", {}).get("derived.capacity_unit") == "BYTES"
        for c in pattern["claims"]
    )
    assert any(
        c.get("id") == "C19"
        and c.get("equals", {}).get("derived.byte_capacity_known") is True
        for c in pattern["claims"]
    )


def test_partial_graph_does_not_infer_argument_index_from_incomplete_argument_edges():
    from evidencelab.parsers import parse_graph
    from evidencelab.canonical import canonicalize_graph

    p = (
        ROOT
        / "examples/cwe-121/families/fixed-write/graphs/fixed_unknown_partial_06.json"
    )
    g = canonicalize_graph(parse_graph(p))
    d = g.nodes["e"].properties.get("derived", {})
    assert "argument_index" not in d
    assert (
        g.nodes["e"]
        .properties.get("derived_provenance", {})
        .get("argument_index", "")
        .startswith("UNKNOWN:")
    )
