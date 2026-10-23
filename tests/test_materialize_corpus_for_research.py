import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "materialize_corpus_for_research.py"
)

SPEC = importlib.util.spec_from_file_location(
    "materialize_corpus_for_research",
    SCRIPT,
)
assert SPEC is not None and SPEC.loader is not None

MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


def make_inputs(tmp_path, *, graph_ref="graphs/input.json", source_ref="source.c"):
    corpus = tmp_path / "corpus"
    (corpus / "graphs").mkdir(parents=True)
    (corpus / "graphs" / "input.json").write_text(
        '{"nodes": [], "edges": []}\n',
        encoding="utf-8",
    )

    source = corpus / "source.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    benchmark = {
        "schema_version": "1.0",
        "manifest_id": "test-corpus",
        "metadata": {"purpose": "contract-test"},
        "cases": [
            {
                "id": "case-001",
                "label": "MATCH",
                "graph": graph_ref,
                "source": source_ref,
                "tags": ["contract", "regression"],
                "dataset": {
                    "name": "synthetic-test",
                    "label_source": "test-fixture",
                },
            }
        ],
    }

    benchmark_path = corpus / "benchmark.json"
    benchmark_path.write_text(
        json.dumps(benchmark, indent=2),
        encoding="utf-8",
    )

    pattern_root = tmp_path / "patterns"
    family_dir = pattern_root / "test-family"
    family_dir.mkdir(parents=True)
    (family_dir / "pattern.json").write_text(
        '{"id": "test-pattern"}\n',
        encoding="utf-8",
    )

    return corpus, benchmark_path, pattern_root, source


def test_materializer_preserves_case_identity_labels_and_provenance(tmp_path):
    corpus, benchmark_path, pattern_root, source = make_inputs(tmp_path)
    out_root = tmp_path / "evaluation"

    report = MATERIALIZER.materialize(
        benchmark_path,
        pattern_root,
        out_root,
    )

    family_dir = out_root / "families" / "test-family"
    result = json.loads((family_dir / "benchmark.json").read_text(encoding="utf-8"))
    case = result["cases"][0]

    assert report["status"] == "PASS"
    assert report["case_count"] == 1
    assert report["family_count"] == 1

    assert result["manifest_id"] == "test-corpus-test-family"
    assert result["metadata"]["materialized_for_pattern"] == "test-family"

    assert case["id"] == "case-001"
    assert case["label"] == "MATCH"
    assert case["tags"] == ["contract", "regression"]
    assert case["dataset"] == {
        "name": "synthetic-test",
        "label_source": "test-fixture",
    }

    copied_graph = family_dir / case["graph"]
    copied_source = family_dir / case["source"]

    assert copied_graph.is_file()
    assert copied_source.is_file()
    assert copied_graph.read_bytes() == (corpus / "graphs" / "input.json").read_bytes()
    assert copied_source.read_bytes() == source.read_bytes()

    assert "does not make them independently validated ground truth" in (report["note"])


def test_materializer_reports_missing_source_without_inventing_one(tmp_path):
    _, benchmark_path, pattern_root, _ = make_inputs(
        tmp_path,
        source_ref="missing.c",
    )

    report = MATERIALIZER.materialize(
        benchmark_path,
        pattern_root,
        tmp_path / "evaluation",
    )

    family = report["families"][0]
    result_path = (
        tmp_path / "evaluation" / "families" / "test-family" / "benchmark.json"
    )
    case = json.loads(result_path.read_text(encoding="utf-8"))["cases"][0]

    assert report["status"] == "PASS"
    assert family["source_files_missing"] == 1
    assert family["missing_sources"][0]["id"] == "case-001"

    assert "source" not in case
    assert case["source_missing_original"] == "missing.c"
    assert case["source_missing_reason"]


def test_materializer_rejects_graph_reference_outside_corpus(tmp_path):
    outside_graph = tmp_path / "outside.json"
    outside_graph.write_text('{"nodes": [], "edges": []}\n', encoding="utf-8")

    _, benchmark_path, pattern_root, _ = make_inputs(
        tmp_path,
        graph_ref="../outside.json",
    )

    with pytest.raises(ValueError, match="outside the allowed roots"):
        MATERIALIZER.materialize(
            benchmark_path,
            pattern_root,
            tmp_path / "evaluation",
        )


def test_materializer_rejects_source_outside_allowed_roots(tmp_path):
    outside_source = tmp_path / "outside.c"
    outside_source.write_text("int outside;\n", encoding="utf-8")

    _, benchmark_path, pattern_root, _ = make_inputs(
        tmp_path,
        source_ref=str(outside_source),
    )

    with pytest.raises(ValueError, match="outside the allowed roots"):
        MATERIALIZER.materialize(
            benchmark_path,
            pattern_root,
            tmp_path / "evaluation",
        )


def test_materializer_rejects_missing_graph(tmp_path):
    _, benchmark_path, pattern_root, _ = make_inputs(tmp_path)

    benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    benchmark["cases"][0]["graph"] = "graphs/does-not-exist.json"
    benchmark_path.write_text(json.dumps(benchmark), encoding="utf-8")

    with pytest.raises(ValueError, match="graph assets are missing"):
        MATERIALIZER.materialize(
            benchmark_path,
            pattern_root,
            tmp_path / "evaluation",
        )
