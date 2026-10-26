import json
import os
from pathlib import Path

import pytest

from evidencelab import corpus_runner


def _manifest(tmp_path, cases):
    root = tmp_path / "source"
    root.mkdir()
    (root / "safe.c").write_text("int safe(void) { return 0; }\n", encoding="utf-8")
    (root / "vulnerable.cpp").write_text("int vulnerable() { return 1; }\n", encoding="utf-8")
    path = root / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "dataset": {
                    "id": "source-test",
                    "name": "Source test",
                    "version": "1",
                    "label_authority": "reviewed-ground-truth",
                },
                "cases": cases,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_capture_source_dataset_writes_labeled_outputs_and_rewrites_graph_paths(
    tmp_path, monkeypatch
):
    manifest = _manifest(
        tmp_path,
        [
            {"id": "safe-case", "source": "safe.c", "label": "SAFE"},
            {
                "id": "vulnerable-case",
                "source": "vulnerable.cpp",
                "label": "vulnerable",
                "source_metadata": {"revision": "abc123"},
            },
        ],
    )

    def fake_capture_dataset(
        dataset_manifest,
        out_dir,
        benchmark_out,
        timeout,
        slice_depth,
        best_effort,
        limit,
        keep_failures_as_unknown,
    ):
        out = Path(out_dir)
        graph_paths = {}
        for case_id in ("safe-case", "vulnerable-case"):
            graph = out / case_id / "canonical-graph.json"
            graph.parent.mkdir(parents=True)
            graph.write_text('{"nodes": [], "edges": []}\n', encoding="utf-8")
            graph_paths[case_id] = graph
        capture_manifest = out / "safe-case" / "capture-manifest.json"
        capture_manifest.write_text("{}\n", encoding="utf-8")
        raw = json.loads(Path(dataset_manifest).read_text(encoding="utf-8"))
        cases = []
        for source_case in raw["cases"]:
            case_id = source_case["id"]
            item = dict(source_case)
            item["graph"] = os.path.relpath(graph_paths[case_id], Path(dataset_manifest).parent)
            item["capture"] = {
                "status": "PASS" if case_id == "safe-case" else "FAILED",
                "manifest": os.path.relpath(capture_manifest, Path(dataset_manifest).parent),
            }
            if case_id == "vulnerable-case":
                item["analysis"] = {"status": "UNKNOWN", "reason": "CAPTURE_FAILED"}
            cases.append(item)
        Path(benchmark_out).write_text(
            json.dumps({"cases": cases}), encoding="utf-8"
        )
        return {
            "status": "DEGRADED",
            "requested": 2,
            "captured": 1,
            "failed": 1,
            "unknown_from_failures": 1,
            "failures": [{"id": "vulnerable-case", "error": "capture failed"}],
            "benchmark": str(benchmark_out),
        }

    monkeypatch.setattr(corpus_runner, "capture_dataset", fake_capture_dataset)
    out = tmp_path / "output"
    result = corpus_runner.capture_source_dataset(manifest, out)

    safe = json.loads((out / "safe.json").read_text(encoding="utf-8"))
    vulnerable = json.loads((out / "vulnerable.json").read_text(encoding="utf-8"))

    assert result["status"] == "DEGRADED"
    assert safe["label"] == "safe"
    assert [case["id"] for case in safe["cases"]] == ["safe-case"]
    assert safe["cases"][0]["label_authority"] == "reviewed-ground-truth"
    assert (out / safe["cases"][0]["graph"]).is_file()
    assert vulnerable["cases"][0]["label"] == "vulnerable"
    assert vulnerable["cases"][0]["capture"]["status"] == "FAILED"
    assert vulnerable["cases"][0]["analysis"]["status"] == "UNKNOWN"
    assert vulnerable["cases"][0]["source_metadata"] == {"revision": "abc123"}


def test_capture_source_dataset_rejects_unknown_labels_before_capture(tmp_path):
    manifest = _manifest(
        tmp_path,
        [{"id": "case-1", "source": "safe.c", "label": "unknown"}],
    )

    with pytest.raises(ValueError, match="label must be safe or vulnerable"):
        corpus_runner.capture_source_dataset(manifest, tmp_path / "output")


def test_capture_source_dataset_rejects_source_paths_outside_manifest_root(tmp_path):
    manifest = _manifest(
        tmp_path,
        [{"id": "case-1", "source": "../outside.c", "label": "safe"}],
    )

    with pytest.raises(ValueError, match="escapes manifest directory"):
        corpus_runner.capture_source_dataset(manifest, tmp_path / "output")


def test_capture_source_dataset_retains_labels_when_real_capture_fails(
    tmp_path, monkeypatch
):
    manifest = _manifest(
        tmp_path,
        [{"id": "vulnerable-case", "source": "vulnerable.cpp", "label": "vulnerable"}],
    )

    def fail_capture(*args, **kwargs):
        raise RuntimeError("Joern unavailable")

    monkeypatch.setattr(corpus_runner, "capture_joern", fail_capture)
    out = tmp_path / "output"
    result = corpus_runner.capture_source_dataset(manifest, out)

    vulnerable = json.loads((out / "vulnerable.json").read_text(encoding="utf-8"))
    assert result["status"] == "DEGRADED"
    assert len(vulnerable["cases"]) == 1
    assert vulnerable["cases"][0]["label"] == "vulnerable"
    assert vulnerable["cases"][0]["capture"]["status"] == "FAILED"
    assert vulnerable["cases"][0]["analysis"]["status"] == "UNKNOWN"
