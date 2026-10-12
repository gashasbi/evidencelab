from __future__ import annotations

import json
from pathlib import Path
import pytest

from evidencelab.dataset_model import materialize, validate_model
from evidencelab.provenance import sha256_file, sha256_json
from evidencelab.evidence_dsl import compile_els_file, validate_els
from evidencelab.matcher import Matcher
from evidencelab.parsers import parse_graph
from evidencelab.spec import Pattern
from evidencelab import SCHEMA_VERSION, __version__

ROOT = Path(__file__).resolve().parents[1]
ELS = ROOT / "examples/evidence-dsl/cwe121-fixed-write-research-grade.els"
GRAPH = ROOT / "examples/cwe-121/graphs/vulnerable.json"
MODEL = ROOT / "examples/dataset-model/simple-vuln-dataset.json"


def test_public_release_identity():
    assert __version__ == "1.0.0"
    assert SCHEMA_VERSION == "1.0"


def test_els_validates_and_compiles_to_current_pattern():
    result = validate_els(ELS)
    assert result["status"] == "PASS", result
    raw = compile_els_file(ELS)
    assert raw["schema_version"] == "1.0"
    assert raw["evidence_contract"]["tri_state"] is True
    assert raw["semantic_contract"]["analyzer_independent"] is True
    assert Pattern.from_dict(raw).pattern_id == "cwe-121.fixed-write-001"


def test_els_runs_against_canonical_graph_and_emits_trace():
    raw = compile_els_file(ELS)
    pattern = Pattern.from_dict(raw)
    graph = parse_graph(GRAPH)
    result = Matcher(graph).run(pattern).to_dict()
    assert result["status"] == "MATCH", result
    assert result["witnesses"][0]["status"] == "MATCH"
    assert result["witnesses"][0]["bindings"]["target"] == "4"
    assert result["witnesses"][0]["bindings"]["extent"] == "5"
    assert result["evidence_trace"]["schema_version"] == "1.0"
    assert result["evidence_trace"]["analysis_incomplete"] is False
    assert result["evidence_trace"]["witness_search_complete"] is True
    assert result["ledger"]["schema_version"] == "1.0"


def test_dataset_model_is_explicit_and_preserves_source_record():
    result = validate_model(MODEL)
    assert result["status"] == "PASS", result
    data = materialize(MODEL)

    model_data = json.loads(MODEL.read_text(encoding="utf-8"))
    assert result["mapping_digest"] == sha256_json(model_data)
    assert data["mapping_sha256"] == sha256_file(MODEL)
    assert data["schema_version"] == "1.0"
    assert data["case_count"] == 3
    by_id = {x["id"]: x for x in data["cases"]}
    assert by_id["V-001"]["truth"]["state"] == "BAD"
    assert by_id["V-002"]["truth"]["state"] == "GOOD"
    assert by_id["V-003"]["truth"]["state"] == "UNKNOWN"
    assert by_id["V-001"]["source_record"]["label"] == "bad"
    assert by_id["V-001"]["claims"][0]["value"] == "CWE-121"
    assert by_id["V-001"]["artifacts"][0]["status"] == "READY"


def test_dataset_mapping_digest_ignores_formatting_but_file_sha_does_not(
    tmp_path: Path,
):
    model_data = json.loads(MODEL.read_text(encoding="utf-8"))
    reformatted = tmp_path / "reformatted-model.json"
    reformatted.write_text(
        json.dumps(model_data, ensure_ascii=False, indent=4, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    original_result = validate_model(MODEL)
    reformatted_result = validate_model(reformatted)

    assert original_result["status"] == "PASS", original_result
    assert reformatted_result["status"] == "PASS", reformatted_result

    assert (
        original_result["mapping_digest"]
        == reformatted_result["mapping_digest"]
    )
    assert sha256_file(MODEL) != sha256_file(reformatted)


def test_dataset_model_rejects_absolute_and_escape_paths(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "cases.jsonl").write_text(
        json.dumps({"id": "x", "label": "bad", "source": "../outside.c"}) + "\n"
    )
    outside = tmp_path / "outside.c"
    outside.write_text("int x;\n")
    model = {
        "schema_version": "1.0",
        "dataset": {"id": "bad-path", "name": "Bad Path", "version": "1.0.0"},
        "source_root": "src",
        "input": {"type": "records", "path": "cases.jsonl", "format": "jsonl"},
        "case": {
            "id": {"path": "id", "transform": "string"},
            "truth": {"state": {"path": "label", "transform": "truth"}},
            "artifacts": [
                {
                    "id": "source",
                    "kind": "source",
                    "path": {"path": "source", "transform": "string"},
                }
            ],
        },
    }
    mp = tmp_path / "model.json"
    mp.write_text(json.dumps(model))
    with pytest.raises(PermissionError):
        materialize(mp)


def test_trace_lists_witness_claims_as_proved(tmp_path: Path):
    raw = compile_els_file(ELS)
    result = Matcher(parse_graph(GRAPH)).run(Pattern.from_dict(raw)).to_dict()
    assert result["status"] == "MATCH"
    proved = set(result["evidence_trace"]["proved_claims"])
    assert {f"C{i}" for i in range(1, 13)} <= proved
    # Compare provenance records operand values, not graph node IDs.
    compare_items = [x for x in result["ledger"]["items"] if x["id"] == "CLAIM:C11"]
    assert compare_items
    assert not any(
        p["source_type"] == "graph" and p["source_id"] in {"256", "32"}
        for p in compare_items[0]["provenance"]
    )


def test_incomplete_graph_preserves_unknown(tmp_path: Path):
    graph = {
        "$type": "DataFlowSlice",
        "metadata": {"completeness": "partial", "parse_health": "OK"},
        "nodes": [
            {
                "id": "s",
                "label": "METHOD_PARAMETER_IN",
                "code": "char *input",
                "name": "input",
            },
            {
                "id": "k",
                "label": "CALL",
                "code": "memcpy(buffer,input,n)",
                "name": "memcpy",
            },
        ],
        "edges": [],
    }
    gp = tmp_path / "partial.json"
    gp.write_text(json.dumps(graph))
    result = (
        Matcher(parse_graph(gp)).run(Pattern.from_dict(compile_els_file(ELS))).to_dict()
    )
    assert result["status"] in {"UNKNOWN", "PARTIAL"}
    assert result["status"] != "MATCH"


def test_els_rejects_unsupported_semantics():
    bad = 'evidence "bad" {\n  cwe "CWE-121"\n  made_up_semantics true\n}'
    from evidencelab.evidence_dsl import compile_els, ELSParseError

    try:
        compile_els(bad)
    except ELSParseError:
        pass
    else:
        raise AssertionError("unsupported ELS key was accepted")


def test_publication_ci_gate_missing_is_reported_not_crashed(tmp_path: Path):
    from evidencelab.profile import validate_benchmark_gate

    metrics = {
        "total": 1,
        "known": 1,
        "tp": 1,
        "fp": 0,
        "tn": 0,
        "fn": 0,
        "expected_unknown": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "specificity": None,
        "balanced_accuracy": None,
        "false_positive_rate": 0.0,
    }
    profile = {"gates": {"min_ci_lower_bounds": {"precision": 0.9}}}
    errors = validate_benchmark_gate(metrics, {"benchmark_audit": {}}, profile)
    assert any("CI lower-bound gate unavailable" in e for e in errors)


def test_fixed_write_extent_binding_and_symbolic_unknown_regression(tmp_path: Path):
    pattern = Pattern.from_dict(compile_els_file(ELS))

    def run(graph_path: Path):
        return Matcher(parse_graph(graph_path)).run(pattern).to_dict()

    positive = run(GRAPH)
    assert positive["status"] == "MATCH", positive
    pos_witness = positive["witnesses"][0]
    pos_claims = {c["claim_id"]: c for c in pos_witness["claims"]}
    assert pos_witness["bindings"]["extent"] == "5"
    assert pos_claims["C5"]["matches"][0]["code"] == "64"
    assert pos_claims["C11"]["status"] == "PROVEN"
    assert pos_claims["C11"]["matches"][0]["left"] == 64
    assert pos_claims["C11"]["matches"][0]["right"] == 32
    assert pos_claims["C12"]["status"] == "PROVEN"

    safe = run(ROOT / "examples/cwe-121/graphs/safe.json")
    assert safe["status"] == "NO_MATCH", safe
    safe_witness = safe["witnesses"][0]
    safe_claims = {c["claim_id"]: c for c in safe_witness["claims"]}
    assert safe_claims["C5"]["matches"][0]["code"] == "16"
    assert safe_claims["C11"]["status"] == "DISPROVEN"
    assert safe_claims["C11"]["matches"][0]["left"] == 16
    assert safe_claims["C11"]["matches"][0]["right"] == 32
    assert safe_claims["C12"]["status"] == "PROVEN"

    raw = json.loads(GRAPH.read_text(encoding="utf-8"))
    extent_node = next(node for node in raw["nodes"] if str(node["id"]) == "5")
    extent_node.update(
        {
            "type": "IDENTIFIER",
            "name": "n",
            "code": "n",
            "typeFullName": "size_t",
        }
    )
    symbolic_path = tmp_path / "symbolic-extent.json"
    symbolic_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")

    symbolic = run(symbolic_path)
    assert symbolic["status"] == "UNKNOWN", symbolic
    sym_witness = symbolic["witnesses"][0]
    sym_claims = {c["claim_id"]: c for c in sym_witness["claims"]}
    assert sym_claims["C5"]["matches"][0]["code"] == "n"
    assert sym_claims["C11"]["status"] == "UNKNOWN"
    assert sym_claims["C12"]["status"] == "PROVEN"
