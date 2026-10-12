from pathlib import Path

import evidencelab.capture as cap


def test_capture_removes_stale_joern_export_directories(tmp_path, monkeypatch):
    root = tmp_path / "capture"
    source = tmp_path / "sample.c"
    source.write_text("int main(void){return 0;}\n", encoding="utf-8")
    root.mkdir()
    (root / "graphml").mkdir()
    (root / "graphml" / "stale.xml").write_text("stale", encoding="utf-8")
    (root / "graphson").mkdir()
    (root / "graphson" / "stale.json").write_text("stale", encoding="utf-8")
    (root / "dataflow.json").write_text("stale", encoding="utf-8")
    (root / "cpg.bin").write_bytes(b"stale")

    commands = []

    monkeypatch.setattr(cap.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(cap, "joern_version", lambda: "4.0.646")

    def fake_run(cmd, cwd=None, timeout=1800):
        commands.append(cmd)
        if cmd[0] == "joern-parse":
            Path(cmd[-1]).write_bytes(b"cpg")
        elif cmd[0] == "joern-export":
            out = Path(cmd[-1])
            assert not out.exists(), f"Joern export directory must not pre-exist: {out}"
            out.mkdir()
            (
                out / ("export.xml" if cmd[3] == "--format=graphml" else "export.json")
            ).write_text("{}", encoding="utf-8")
        elif cmd[0] == "joern-slice":
            Path(str(cmd[-1]) + ".json").write_text(
                '{"$type":"DataFlowSlice","nodes":[],"edges":[]}', encoding="utf-8"
            )
        return "", ""

    monkeypatch.setattr(cap, "_run", fake_run)
    result = cap.capture_joern(source, root)

    assert result["joern_version"] == "4.0.646"
    assert (root / "graphml" / "export.xml").is_file()
    assert (root / "graphson" / "export.json").is_file()
    assert (root / "dataflow.json").is_file()
    assert (root / "cpg.bin").read_bytes() == b"cpg"
    assert len(commands) == 4
