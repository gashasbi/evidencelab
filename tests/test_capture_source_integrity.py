import hashlib
from pathlib import Path

import pytest

import evidencelab.capture as cap
from evidencelab.errors import EvidenceLabError


GRAPHML = (
    '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">'
    '<graph id="G" edgedefault="directed"><node id="1"/></graph>'
    '</graphml>'
)


def _capture(monkeypatch, tmp_path, *, change_source):
    source = tmp_path / "sample.c"
    source.write_text(
        "int main(void) { return 0; }\n",
        encoding="utf-8",
    )
    initial_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "capture"
    if change_source:
        output.mkdir()
        (output / "capture-manifest.json").write_text(
            '{"status":"PASS"}',
            encoding="utf-8",
        )

    monkeypatch.setattr(cap.shutil, "which", lambda name: f"/mock/{name}")
    monkeypatch.setattr(cap, "joern_version", lambda: "test-version")

    def fake_run(cmd, cwd=None, timeout=1800):
        if cmd[0] == "joern-parse":
            Path(cmd[-1]).write_bytes(b"cpg")
        elif cmd[0] == "joern-export":
            export_dir = Path(cmd[-1])
            assert not export_dir.exists()
            export_dir.mkdir(parents=True)
            (export_dir / "export.xml").write_text(
                GRAPHML,
                encoding="utf-8",
            )
            if change_source:
                source.write_text(
                    "int main(void) { return 1; }\n",
                    encoding="utf-8",
                )
        return "", ""

    monkeypatch.setattr(cap, "_run", fake_run)
    manifest = cap.capture_joern(
        source,
        output,
        graphson=False,
        dataflow=False,
    )
    return manifest, output, initial_hash


def test_manifest_uses_the_verified_source_digest(monkeypatch, tmp_path):
    manifest, _output, initial_hash = _capture(
        monkeypatch,
        tmp_path,
        change_source=False,
    )

    assert manifest["source_sha256"] == initial_hash
    assert manifest["analysis_attestation"]["source_sha256"] == initial_hash


def test_capture_rejects_source_changes_during_analysis(monkeypatch, tmp_path):
    with pytest.raises(EvidenceLabError, match="source changed during capture"):
        _capture(
            monkeypatch,
            tmp_path,
            change_source=True,
        )

    assert not (tmp_path / "capture" / "capture-manifest.json").exists()
