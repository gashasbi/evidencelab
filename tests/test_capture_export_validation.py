from pathlib import Path

import pytest

import evidencelab.capture as cap
from evidencelab.errors import EvidenceLabError
from evidencelab.parsers import parse_graphml, parse_graphson

VALID_GRAPHML = (
    '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">'
    '<graph id="G" edgedefault="directed">'
    '<node id="1"/><node id="2"/>'
    '<edge id="e1" source="1" target="2"/>'
    "</graph></graphml>"
)
VALID_GRAPHSON = '{"vertices":[{"id":1,"label":"METHOD","properties":{}}],"edges":[]}'


def _capture(
    monkeypatch,
    tmp_path,
    *,
    graphml_payload=VALID_GRAPHML,
    graphson_payload=VALID_GRAPHSON,
    graphml_filename="export.xml",
    graphson_filename="export.json",
    graphson=True,
):
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
                if graphml_payload is not None:
                    (export_dir / graphml_filename).write_text(
                        graphml_payload, encoding="utf-8"
                    )
            elif graphson_payload is not None:
                (export_dir / graphson_filename).write_text(
                    graphson_payload, encoding="utf-8"
                )
        return "", ""

    monkeypatch.setattr(cap, "_run", fake_run)
    manifest = cap.capture_joern(source, output, graphson=graphson, dataflow=False)
    return manifest, output


def test_valid_graph_exports_are_recorded_and_readable(monkeypatch, tmp_path):
    manifest, _output = _capture(monkeypatch, tmp_path)

    graphml_path = Path(manifest["artifacts"]["graphml"])
    graphson_path = Path(manifest["artifacts"]["graphson"])

    assert graphml_path.is_file()
    assert graphson_path.is_file()
    assert parse_graphml(graphml_path).nodes
    assert parse_graphson(graphson_path).nodes
    assert manifest["status"] == "PASS"


def test_missing_graphml_export_fails_capture(monkeypatch, tmp_path):
    with pytest.raises(EvidenceLabError, match="no GraphML file"):
        _capture(
            monkeypatch,
            tmp_path,
            graphml_payload=None,
            graphson=False,
        )


@pytest.mark.parametrize(
    "payload",
    [
        "<graphml/>",
        "<not-graphml/>",
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph id="G" edgedefault="directed"><node id="1"/><edge id="e1" source="1" target="2"/></graph></graphml>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph id="G" edgedefault="directed"><node id="1"/><node id="1"/></graph></graphml>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph id="G" edgedefault="directed"/></graphml>',
        "not xml",
    ],
)
def test_invalid_or_empty_graphml_export_fails_capture(monkeypatch, tmp_path, payload):
    with pytest.raises(EvidenceLabError, match="GraphML"):
        _capture(
            monkeypatch,
            tmp_path,
            graphml_payload=payload,
            graphson=False,
        )


def test_graphml_rejects_declarations_after_long_preamble(monkeypatch, tmp_path):
    payload = (
        '<?xml version="1.0"?>'
        + (" " * 9000)
        + '<!DOCTYPE graphml [<!ENTITY sample "value">]>'
        + '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">'
        + '<graph id="G" edgedefault="directed"><node id="1"/></graph>'
        + "</graphml>"
    )

    with pytest.raises(EvidenceLabError, match="DTD/entity declarations"):
        _capture(
            monkeypatch,
            tmp_path,
            graphml_payload=payload,
            graphson=False,
        )


def test_fallback_export_file_must_contain_graphml(monkeypatch, tmp_path):
    with pytest.raises(EvidenceLabError, match="GraphML"):
        _capture(
            monkeypatch,
            tmp_path,
            graphml_payload="not GraphML",
            graphml_filename="export.log",
            graphson=False,
        )


def test_graphson_is_required_when_requested(monkeypatch, tmp_path):
    with pytest.raises(EvidenceLabError, match="no GraphSON file"):
        _capture(monkeypatch, tmp_path, graphson_payload=None)


@pytest.mark.parametrize(
    "payload",
    [
        "{invalid",
        "{}",
        '{"vertices":[],"edges":[]}',
        '{"vertices":[{"label":"METHOD"}],"edges":[]}',
        '{"vertices":[{"id":1,"label":"METHOD","properties":{}}],"edges":[{"outV":1}]}',
    ],
)
def test_invalid_or_empty_graphson_export_fails_capture(monkeypatch, tmp_path, payload):
    with pytest.raises(EvidenceLabError, match="GraphSON"):
        _capture(monkeypatch, tmp_path, graphson_payload=payload)


def test_graphson_edges_must_reference_exported_vertices(monkeypatch, tmp_path):
    payload = (
        '{"vertices":[{"id":1,"label":"METHOD","properties":{}}],'
        '"edges":[{"outV":1,"inV":2,"label":"CALL"}]}'
    )
    with pytest.raises(EvidenceLabError, match="GraphSON edge with missing endpoints"):
        _capture(monkeypatch, tmp_path, graphson_payload=payload)


def test_graphson_is_optional_when_not_requested(monkeypatch, tmp_path):
    manifest, _output = _capture(
        monkeypatch,
        tmp_path,
        graphson_payload=None,
        graphson=False,
    )

    assert manifest["status"] == "PASS"
    assert manifest["artifacts"]["graphson"] is None
