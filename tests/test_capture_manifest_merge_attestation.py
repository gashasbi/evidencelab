import json

import pytest

from evidencelab.capture import (
    _sha256_path,
    validate_capture_manifest_for_merge,
)
from evidencelab.errors import EvidenceLabError


def make_capture_manifest(tmp_path):
    source = tmp_path / "source.c"
    graphml = tmp_path / "export.xml"
    dataflow = tmp_path / "dataflow.json"

    source.write_text("int main(void) { return 0; }", encoding="utf-8")
    graphml.write_text("<graphml></graphml>", encoding="utf-8")
    dataflow.write_text(
        json.dumps({"nodes": [], "edges": []}),
        encoding="utf-8",
    )

    source_hash = _sha256_path(source)
    graphml_hash = _sha256_path(graphml)
    dataflow_hash = _sha256_path(dataflow)

    manifest = {
        "format": "evidencelab-capture",
        "status": "PASS",
        "source": str(source),
        "source_sha256": source_hash,
        "artifacts": {
            "graphml": str(graphml),
            "dataflow": str(dataflow),
        },
        "merge_input_sha256": {
            "graphml": graphml_hash,
            "dataflow": dataflow_hash,
        },
        "analysis": {"dataflow": {"status": "OK"}},
        "analysis_attestation": {
            "level": "ANALYZER_ATTESTED",
            "analyzer": "Joern",
            "analyzer_version": "test",
            "source_sha256": source_hash,
            "capture_status": "PASS",
        },
    }

    manifest_path = tmp_path / "capture-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    return manifest_path, source, graphml, dataflow


def test_merge_manifest_validates_source_and_inputs(tmp_path):
    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)

    result = validate_capture_manifest_for_merge(
        manifest_path,
        [graphml, dataflow],
    )

    assert result["level"] == "ANALYZER_ATTESTED"
    assert result["integrity_validation"] == "MERGE_INPUTS_VERIFIED"
    assert result["verified_merge_input_sha256"]["graphml"] == _sha256_path(graphml)
    assert result["verified_merge_input_sha256"]["dataflow"] == _sha256_path(dataflow)
    assert result["capture_manifest_sha256"] == _sha256_path(manifest_path)


def test_merge_manifest_rejects_changed_graphml(tmp_path):
    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    graphml.write_text("<graphml>changed</graphml>", encoding="utf-8")

    with pytest.raises(EvidenceLabError, match="graphml artifact hash mismatch"):
        validate_capture_manifest_for_merge(manifest_path, [graphml, dataflow])


def test_merge_manifest_rejects_changed_source(tmp_path):
    manifest_path, source, graphml, dataflow = make_capture_manifest(tmp_path)
    source.write_text("int main(void) { return 1; }", encoding="utf-8")

    with pytest.raises(EvidenceLabError, match="source hash"):
        validate_capture_manifest_for_merge(manifest_path, [graphml, dataflow])


def test_merge_manifest_rejects_unrecorded_merge_input(tmp_path):
    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    extra = tmp_path / "other.json"
    extra.write_text("{}", encoding="utf-8")

    with pytest.raises(EvidenceLabError, match="ordered merge inputs"):
        validate_capture_manifest_for_merge(manifest_path, [graphml, dataflow, extra])


def test_merge_manifest_rejects_missing_integrity_digests(tmp_path):
    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["merge_input_sha256"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EvidenceLabError, match="integrity data"):
        validate_capture_manifest_for_merge(manifest_path, [graphml, dataflow])


def _make_verified_canonical_payload(manifest_path, graphml, dataflow):
    from evidencelab.scanner import _merge

    inputs = [graphml, dataflow]
    merged = _merge(inputs)
    attestation = validate_capture_manifest_for_merge(manifest_path, inputs)

    return {
        "schema_version": "1.0",
        "format": "evidencelab-canonical-graph",
        "digest": merged.digest(),
        "metadata": {
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_attestation": attestation,
            "capture_manifest": str(manifest_path.resolve()),
            "merge_sources": merged.metadata["merge_sources"],
        },
        "nodes": [
            {"id": n.id, "type": n.type, "properties": n.properties}
            for n in merged.nodes.values()
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
            }
            for e in merged.edges
        ],
    }


def test_parser_preserves_verified_analyzer_attestation(tmp_path):
    from evidencelab.canonical import canonicalize_graph
    from evidencelab.parsers import parse_graph

    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    payload = _make_verified_canonical_payload(manifest_path, graphml, dataflow)

    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = parse_graph(graph_path)
    canonical = canonicalize_graph(parsed)

    assert (
        parsed.metadata["analysis_attestation"]
        == (payload["metadata"]["analysis_attestation"])
    )
    assert parsed.metadata["capture_manifest"] == str(manifest_path.resolve())
    assert (
        canonical.metadata["analysis_attestation"]
        == (payload["metadata"]["analysis_attestation"])
    )


def test_parser_rejects_canonical_graph_changed_without_digest_update(tmp_path):
    from evidencelab.parsers import parse_graph

    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    payload = _make_verified_canonical_payload(manifest_path, graphml, dataflow)

    payload["nodes"].append(
        {
            "id": "injected-node",
            "type": "LOCAL",
            "properties": {"name": "injected", "code": "char injected[32]"},
        }
    )

    graph_path = tmp_path / "tampered-stale-digest.json"
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = parse_graph(graph_path)

    assert "analysis_attestation" not in parsed.metadata
    assert parsed.metadata["parse_health"] == "DEGRADED"
    assert (
        "canonical graph digest mismatch"
        in (parsed.metadata["attestation_integrity_error"])
    )


def test_parser_rejects_canonical_graph_changed_with_recomputed_digest(tmp_path):
    from evidencelab.parsers import parse_graph

    manifest_path, _, graphml, dataflow = make_capture_manifest(tmp_path)
    payload = _make_verified_canonical_payload(manifest_path, graphml, dataflow)

    payload["nodes"].append(
        {
            "id": "injected-node",
            "type": "LOCAL",
            "properties": {"name": "injected", "code": "char injected[32]"},
        }
    )

    graph_path = tmp_path / "tampered-recomputed-digest.json"
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    modified_graph = parse_graph(graph_path)
    payload["digest"] = modified_graph.digest()
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = parse_graph(graph_path)

    assert "analysis_attestation" not in parsed.metadata
    assert parsed.metadata["parse_health"] == "DEGRADED"
    assert (
        "canonical graph does not match verified merge inputs"
        in (parsed.metadata["attestation_integrity_error"])
    )


def test_parser_does_not_promote_forged_analyzer_attestation(tmp_path):
    from evidencelab.parsers import parse_graph

    attestation = {
        "level": "ANALYZER_ATTESTED",
        "analyzer": "Joern",
        "capture_status": "PASS",
        "source_sha256": "a" * 64,
        "integrity_validation": "MERGE_INPUTS_VERIFIED",
        "capture_manifest_sha256": "b" * 64,
        "verified_merge_input_sha256": {
            "graphml": "c" * 64,
            "dataflow": "d" * 64,
        },
    }

    payload = {
        "schema_version": "1.0",
        "format": "evidencelab-canonical-graph",
        "metadata": {
            "completeness": "full_export",
            "parse_health": "OK",
            "analysis_attestation": attestation,
            "capture_manifest": str(tmp_path / "missing-capture-manifest.json"),
            "merge_sources": [
                {
                    "path": str(tmp_path / "export.xml"),
                    "sha256": "c" * 64,
                },
                {
                    "path": str(tmp_path / "dataflow.json"),
                    "sha256": "d" * 64,
                },
            ],
        },
        "nodes": [{"id": "local", "type": "LOCAL", "properties": {}}],
        "edges": [],
    }

    graph_path = tmp_path / "forged.json"
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    parsed = parse_graph(graph_path)

    assert "analysis_attestation" not in parsed.metadata
    assert parsed.metadata["declared_metadata"]["analysis_attestation"] == attestation


def test_analyzer_attestation_requires_verified_input_hashes():
    from evidencelab.attestation import is_trusted_attestation

    base = {
        "level": "ANALYZER_ATTESTED",
        "analyzer": "Joern",
        "capture_status": "PASS",
        "source_sha256": "a" * 64,
        "integrity_validation": "MERGE_INPUTS_VERIFIED",
        "capture_manifest_sha256": "b" * 64,
        "verified_merge_input_sha256": {
            "graphml": "c" * 64,
            "dataflow": "d" * 64,
        },
    }

    assert is_trusted_attestation(base)

    bad = dict(base)
    bad["verified_merge_input_sha256"] = {"graphml": "changed"}
    assert not is_trusted_attestation(bad)

    bad = dict(base)
    bad["integrity_validation"] = "UNVERIFIED"
    assert not is_trusted_attestation(bad)

    assert not is_trusted_attestation({"level": "BENCHMARK_ASSERTED"})
