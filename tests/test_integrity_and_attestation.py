import hashlib, json
import pytest
from evidencelab.capture import _sha256_path, validate_capture_manifest_for_merge
from evidencelab.errors import EvidenceLabError
from evidencelab.attestation import is_trusted_attestation


def _manifest(tmp_path):
    src = tmp_path / "source.c"
    graph = tmp_path / "graph.xml"
    flow = tmp_path / "flow.json"
    src.write_text("int main(void){return 0;}\\n", encoding="utf-8")
    graph.write_text("<graphml/>", encoding="utf-8")
    flow.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    sh, gh, fh = map(_sha256_path, (src, graph, flow))
    payload = {
        "format": "evidencelab-capture",
        "status": "PASS",
        "source": str(src),
        "source_sha256": sh,
        "artifacts": {"graphml": str(graph), "dataflow": str(flow)},
        "merge_input_sha256": {"graphml": gh, "dataflow": fh},
        "analysis": {"dataflow": {"status": "OK"}},
        "analysis_attestation": {
            "level": "ANALYZER_ATTESTED",
            "analyzer": "Joern",
            "analyzer_version": "qa",
            "source_sha256": sh,
            "capture_status": "PASS",
        },
    }
    mp = tmp_path / "capture-manifest.json"
    mp.write_text(json.dumps(payload), encoding="utf-8")
    return mp, src, graph, flow


def test_file_hash_matches_sha256_standard(tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(b"abc")
    assert _sha256_path(f) == hashlib.sha256(b"abc").hexdigest()


def test_directory_hash_repeatable_and_content_sensitive(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_text("one", encoding="utf-8")
    h = _sha256_path(root)
    assert _sha256_path(root) == h
    (root / "a.txt").write_text("two", encoding="utf-8")
    assert _sha256_path(root) != h


def test_valid_manifest_attests_exact_ordered_inputs(tmp_path):
    mp, _, graph, flow = _manifest(tmp_path)
    result = validate_capture_manifest_for_merge(mp, [graph, flow])
    assert result["level"] == "ANALYZER_ATTESTED"
    assert result["integrity_validation"] == "MERGE_INPUTS_VERIFIED"


def test_changed_graph_artifact_is_rejected(tmp_path):
    mp, _, graph, flow = _manifest(tmp_path)
    graph.write_text("<graphml>modified</graphml>", encoding="utf-8")
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [graph, flow])


def test_changed_source_is_rejected(tmp_path):
    mp, src, graph, flow = _manifest(tmp_path)
    src.write_text("int main(void){return 1;}\\n", encoding="utf-8")
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [graph, flow])


def test_extra_or_reordered_input_is_rejected(tmp_path):
    mp, _, graph, flow = _manifest(tmp_path)
    extra = tmp_path / "extra.json"
    extra.write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [flow, graph])
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [graph, flow, extra])


def test_trusted_attestation_requires_verified_integrity_fields():
    good = {
        "level": "ANALYZER_ATTESTED",
        "analyzer": "Joern",
        "capture_status": "PASS",
        "source_sha256": "a" * 64,
        "integrity_validation": "MERGE_INPUTS_VERIFIED",
        "capture_manifest_sha256": "b" * 64,
        "verified_merge_input_sha256": {"graphml": "c" * 64, "dataflow": "d" * 64},
    }
    assert is_trusted_attestation(good)
    bad_cases = [
        {"level": "ANALYZER_ATTESTED"},
        {**good, "integrity_validation": "UNVERIFIED"},
        {**good, "verified_merge_input_sha256": {"graphml": "x"}},
        {"level": "BENCHMARK_ASSERTED"},
    ]
    for bad in bad_cases:
        assert not is_trusted_attestation(bad)


def test_directory_hash_ignores_file_mtime(tmp_path):
    import os

    root = tmp_path / "tree"
    root.mkdir()
    f = root / "source.c"
    f.write_text("stable", encoding="utf-8")
    before = _sha256_path(root)
    os.utime(f, (1000000000, 1000000000))
    assert _sha256_path(root) == before


def test_empty_directory_is_part_of_directory_hash(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    before = _sha256_path(root)
    (root / "empty").mkdir()
    assert _sha256_path(root) != before


def test_directory_hash_rejects_missing_path(tmp_path):
    with pytest.raises(EvidenceLabError):
        _sha256_path(tmp_path / "missing")


def test_manifest_rejects_failed_capture_status(tmp_path):
    mp, _, graph, flow = _manifest(tmp_path)
    payload = json.loads(mp.read_text(encoding="utf-8"))
    payload["status"] = "FAIL"
    mp.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [graph, flow])


def test_manifest_rejects_missing_or_untrusted_attestation(tmp_path):
    mp, _, graph, flow = _manifest(tmp_path)
    payload = json.loads(mp.read_text(encoding="utf-8"))
    payload["analysis_attestation"] = {
        "level": "BENCHMARK_ASSERTED",
        "analyzer": "unknown",
    }
    mp.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(EvidenceLabError):
        validate_capture_manifest_for_merge(mp, [graph, flow])
