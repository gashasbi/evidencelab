from pathlib import Path
import subprocess

import pytest

import evidencelab.capture as cap
from evidencelab.errors import EvidenceLabError


def _capture_with_slice_action(monkeypatch, tmp_path, slice_action, *, best_effort):
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "capture"

    monkeypatch.setattr(cap.shutil, "which", lambda name: f"/mock/{name}")
    monkeypatch.setattr(cap, "joern_version", lambda: "test-version")

    def fake_run(cmd, cwd=None, timeout=1800):
        if cmd[0] == "joern-parse":
            Path(cmd[-1]).write_bytes(b"cpg")
        elif cmd[0] == "joern-export":
            export_dir = Path(cmd[-1])
            assert not export_dir.exists()
            export_dir.mkdir(parents=True)
            if "--format=graphml" in cmd:
                (export_dir / "export.xml").write_text(
                    "<graphml/>", encoding="utf-8"
                )
            else:
                (export_dir / "export.json").write_text("{}", encoding="utf-8")
        elif cmd[0] == "joern-slice":
            output_file = Path(str(Path(cmd[-1])) + ".json")
            slice_action(output_file)
        return "", ""

    monkeypatch.setattr(cap, "_run", fake_run)
    manifest = cap.capture_joern(source, output, best_effort_dataflow=best_effort)
    return manifest, output


def test_missing_dataflow_output_fails_capture(monkeypatch, tmp_path):
    def produce_nothing(_output_file):
        return None

    with pytest.raises(EvidenceLabError, match="produced no JSON output"):
        _capture_with_slice_action(
            monkeypatch, tmp_path, produce_nothing, best_effort=False
        )

    assert not (tmp_path / "capture" / "dataflow.json").exists()
    assert not (tmp_path / "capture" / "capture-manifest.json").exists()


def test_best_effort_missing_output_marks_capture_degraded(monkeypatch, tmp_path):
    def produce_nothing(_output_file):
        return None

    manifest, output = _capture_with_slice_action(
        monkeypatch, tmp_path, produce_nothing, best_effort=True
    )

    assert manifest["status"] == "DEGRADED"
    assert manifest["analysis"]["dataflow"]["status"] == "FAILED"
    assert manifest["artifacts"]["dataflow"] is None
    assert manifest["commands"]["dataflow"]["status"] == "FAILED"
    assert not (output / "dataflow.json").exists()


def test_best_effort_command_failure_removes_partial_output(monkeypatch, tmp_path):
    def write_partial_then_fail(output_file: Path):
        output_file.write_text("{partial", encoding="utf-8")
        raise EvidenceLabError("simulated Joern command failure")

    manifest, output = _capture_with_slice_action(
        monkeypatch, tmp_path, write_partial_then_fail, best_effort=True
    )

    assert manifest["status"] == "DEGRADED"
    assert manifest["analysis"]["dataflow"]["status"] == "FAILED"
    assert manifest["artifacts"]["dataflow"] is None
    assert manifest["commands"]["dataflow"]["status"] == "FAILED"
    assert not (output / "dataflow.json").exists()


def test_best_effort_invalid_json_removes_output(monkeypatch, tmp_path):
    def write_invalid_json(output_file: Path):
        output_file.write_text("{partial", encoding="utf-8")

    manifest, output = _capture_with_slice_action(
        monkeypatch, tmp_path, write_invalid_json, best_effort=True
    )

    assert manifest["status"] == "DEGRADED"
    assert manifest["analysis"]["dataflow"]["status"] == "FAILED"
    assert manifest["artifacts"]["dataflow"] is None
    assert not (output / "dataflow.json").exists()


@pytest.mark.parametrize(
    "payload",
    [
        "{}",
        '{"nodes": [], "edges": []}',
        '{"$type": "Other", "nodes": [], "edges": []}',
        '{"$type": "DataFlowSlice", "nodes": {}, "edges": []}',
        '{"$type": "DataFlowSlice", "nodes": [{}], "edges": []}',
        '{"$type": "DataFlowSlice", "nodes": [], "edges": [{"src": 1}]}',
    ],
)
def test_best_effort_rejects_invalid_dataflow_schema(
    monkeypatch, tmp_path, payload
):
    def write_payload(output_file: Path):
        output_file.write_text(payload, encoding="utf-8")

    manifest, output = _capture_with_slice_action(
        monkeypatch, tmp_path, write_payload, best_effort=True
    )

    assert manifest["status"] == "DEGRADED"
    assert manifest["analysis"]["dataflow"]["status"] == "FAILED"
    assert manifest["artifacts"]["dataflow"] is None
    assert manifest["commands"]["dataflow"]["status"] == "FAILED"
    assert not (output / "dataflow.json").exists()


def test_best_effort_timeout_removes_partial_output(monkeypatch, tmp_path):
    def write_then_timeout(output_file: Path):
        output_file.write_text(
            '{"$type":"DataFlowSlice","nodes":[],"edges":[]}',
            encoding="utf-8",
        )
        raise subprocess.TimeoutExpired(
            ["joern-slice", "data-flow"], 1, output="", stderr=""
        )

    manifest, output = _capture_with_slice_action(
        monkeypatch, tmp_path, write_then_timeout, best_effort=True
    )

    assert manifest["status"] == "DEGRADED"
    assert manifest["analysis"]["dataflow"]["status"] == "TIMEOUT"
    assert manifest["artifacts"]["dataflow"] is None
    assert manifest["commands"]["dataflow"]["status"] == "TIMEOUT"
    assert not (output / "dataflow.json").exists()
