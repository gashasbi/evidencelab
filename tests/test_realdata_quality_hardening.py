from __future__ import annotations

import json
from pathlib import Path
import sys
import types

from evidencelab.benchmark_quality import _case_dimensions, _real_world_identity
from evidencelab.datasets import _read_rows


def test_dimension_aliases_are_normalized_in_tags_and_dimensions() -> None:
    from_tag = _case_dimensions(
        {"expected": "MATCH", "tags": ["guard_dominance"], "dimensions": []}
    )
    from_dimensions = _case_dimensions(
        {"expected": "MATCH", "tags": [], "dimensions": ["guard_dominance"]}
    )
    assert "control_conditions" in from_tag
    assert "control_conditions" in from_dimensions
    assert "guard_dominance" not in from_dimensions


def test_real_world_label_source_does_not_substitute_for_issue_or_patch() -> None:
    case = {
        "expected": "MATCH",
        "tags": ["real_world"],
        "dataset": {
            "name": "Example corpus",
            "repository": "org/repo",
            "commit": "abc123",
            "label_source": "target column",
            "provenance_url": "https://example.invalid/dataset",
        },
    }
    valid, missing = _real_world_identity(case)
    assert not valid
    assert "dataset.cve/issue/vulnerability_id/patch_context" in missing


def test_real_world_issue_identity_and_label_provenance_are_separate() -> None:
    case = {
        "expected": "MATCH",
        "dataset": {
            "name": "Example corpus",
            "repository": "org/repo",
            "commit": "abc123",
            "cve": "CVE-2024-12345",
            "label_source": "target column",
            "provenance_url": "https://example.invalid/dataset",
        },
    }
    valid, missing = _real_world_identity(case)
    assert valid, missing


def test_parquet_reader_does_not_decode_binary_file_as_text(
    tmp_path: Path, monkeypatch
) -> None:
    parquet = tmp_path / "sample.parquet"
    parquet.write_bytes(b"PAR1\x00\xffbinary")
    expected_rows = [{"target": 1, "project": "org/repo"}]
    calls: list[str] = []

    class FakeTable:
        def to_pylist(self):
            return expected_rows

    fake_parquet = types.ModuleType("pyarrow.parquet")

    def read_table(path):
        calls.append(str(path))
        return FakeTable()

    fake_parquet.read_table = read_table  # type: ignore[attr-defined]
    fake_arrow = types.ModuleType("pyarrow")
    fake_arrow.__path__ = []  # type: ignore[attr-defined]
    fake_arrow.parquet = fake_parquet  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pyarrow", fake_arrow)
    monkeypatch.setitem(sys.modules, "pyarrow.parquet", fake_parquet)

    def forbidden_read_text(*args, **kwargs):
        raise AssertionError("Parquet must never be decoded through Path.read_text")

    monkeypatch.setattr(Path, "read_text", forbidden_read_text)
    assert _read_rows(parquet) == expected_rows
    assert calls == [str(parquet)]


def test_jsonl_reader_still_handles_blank_lines_and_records(tmp_path: Path) -> None:
    source = tmp_path / "records.jsonl"
    source.write_text(
        '\ufeff{"target": 1}\n\n{"target": 0}\n', encoding="utf-8"
    )
    assert _read_rows(source) == [{"target": 1}, {"target": 0}]


def test_research_pipeline_cwe_staging_keeps_source_paths_resolvable(
    tmp_path: Path, monkeypatch
) -> None:
    """Staged source paths and captured artifact paths survive composition."""
    import os

    from evidencelab import research_pipeline

    source_root = tmp_path / "input"
    source_root.mkdir()
    good = source_root / "good.c"
    other = source_root / "other.c"
    good.write_text("int f(void) { return 1; }\\n", encoding="utf-8")
    other.write_text("int g(void) { return 2; }\\n", encoding="utf-8")

    manifest = source_root / "source-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "dataset": {"name": "test"},
                "cases": [
                    {
                        "id": "cwe120",
                        "source": "good.c",
                        "dataset": {"cwe": ["CWE-120"]},
                        "expected": "UNKNOWN",
                    },
                    {
                        "id": "cwe121",
                        "source": "other.c",
                        "dataset": {"cwe": ["CWE-121"]},
                        "expected": "UNKNOWN",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    seen_by_compose: list[dict] = []

    def fake_capture(dataset_manifest, out_dir, benchmark_out, **kwargs):
        staged = Path(dataset_manifest)
        payload = json.loads(staged.read_text(encoding="utf-8"))
        cases = payload["cases"]

        assert [case["id"] for case in cases] == ["cwe120"]
        for case in cases:
            assert Path(case["source"]).is_absolute()
            assert Path(case["source"]).is_file()

        case = dict(cases[0])
        case_dir = Path(out_dir) / case["id"]
        case_dir.mkdir(parents=True, exist_ok=True)

        graph = case_dir / "canonical-graph.json"
        graph.write_text("{}", encoding="utf-8")

        capture_manifest = case_dir / "capture-manifest.json"
        capture_manifest.write_text(
            json.dumps({"status": "PASS"}), encoding="utf-8"
        )

        # Emulate corpus_runner: these paths are relative to the staged input,
        # while benchmark_out is located at the corpus root.
        case["graph"] = os.path.relpath(graph, staged.parent)
        case["capture"] = {
            "status": "PASS",
            "manifest": os.path.relpath(capture_manifest, staged.parent),
        }

        output = Path(benchmark_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"cases": [case]}), encoding="utf-8")

        return {"status": "PASS", "benchmark": str(output)}

    def fake_compose(inputs, output, **kwargs):
        for input_manifest in inputs:
            captured = Path(input_manifest).resolve()
            payload = json.loads(captured.read_text(encoding="utf-8"))

            for case in payload["cases"]:
                graph_path = (captured.parent / case["graph"]).resolve()
                assert graph_path.is_file()
                graph_path.relative_to(captured.parent.resolve())

                source_path = (captured.parent / case["source"]).resolve()
                assert source_path == good.resolve()
                assert source_path.is_file()

                capture_path = (
                    captured.parent / case["capture"]["manifest"]
                ).resolve()
                assert capture_path.is_file()
                capture_path.relative_to(captured.parent.resolve())

                seen_by_compose.append(case)

        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps({"cases": []}), encoding="utf-8")
        return {"status": "PASS", "case_count": 0}

    monkeypatch.setattr(research_pipeline, "capture_dataset", fake_capture)
    monkeypatch.setattr(research_pipeline, "compose_benchmarks", fake_compose)

    research_pipeline.build_external_research_corpus(
        [manifest],
        tmp_path / "campaign",
        cwe="CWE-120",
        capture=True,
        split=False,
    )

    assert len(seen_by_compose) == 1
    assert seen_by_compose[0]["graph"].startswith("captures/")
    assert seen_by_compose[0]["capture"]["manifest"].startswith("captures/")


def test_primevul_import_preserves_exact_source_bytes_and_hash(tmp_path: Path) -> None:
    import hashlib
    from evidencelab.datasets import import_primevul_jsonl

    code = "int vulnerable(void) { return 7; }"  # Deliberately no final newline.
    source_file = tmp_path / "primevul.jsonl"
    source_file.write_text(
        json.dumps({"func": code, "target": 1, "project": "org/repo", "commit_id": "abc", "cwe": [120]}) + "\n",
        encoding="utf-8",
    )
    output_root = tmp_path / "primevul-sources"
    manifest = tmp_path / "primevul.manifest.json"
    result = import_primevul_jsonl(source_file, manifest, output_root, cwe="CWE-120")
    assert result["case_count"] == 1
    row = json.loads(manifest.read_text(encoding="utf-8"))["cases"][0]
    saved_source = manifest.parent / row["source"]
    assert saved_source.read_text(encoding="utf-8") == code
    assert hashlib.sha256(saved_source.read_bytes()).hexdigest() == row["source_content_sha256"]


def test_secvuleval_import_preserves_exact_source_bytes_and_hash(tmp_path: Path) -> None:
    import hashlib
    from evidencelab.datasets import import_secvuleval_jsonl

    code = "int fixed_record(void) { return 9; }"  # Deliberately no final newline.
    source_file = tmp_path / "secvuleval.jsonl"
    source_file.write_text(
        json.dumps(
            {
                "function_code": code,
                "target": 0,
                "project": "org/another-repo",
                "commit": "def456",
                "CVE": "CVE-2025-54321",
                "patch_diff": "- vulnerable\n+ fixed",
                "date": "2025-01-02T00:00:00Z",
                "cwe": "CWE-120",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output_root = tmp_path / "secvuleval-sources"
    manifest = tmp_path / "secvuleval.manifest.json"
    result = import_secvuleval_jsonl(
        source_file, manifest, output_root, cwe="CWE-120"
    )
    assert result["case_count"] == 1
    row = json.loads(manifest.read_text(encoding="utf-8"))["cases"][0]
    saved_source = manifest.parent / row["source"]
    assert saved_source.read_text(encoding="utf-8") == code
    assert hashlib.sha256(saved_source.read_bytes()).hexdigest() == row["source_content_sha256"]
