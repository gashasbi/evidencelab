from pathlib import Path
import subprocess
from evidencelab.capture import capture_joern


def test_capture_source_signature_supports_bounded_dataflow_controls():
    from inspect import signature

    params = signature(capture_joern).parameters
    for name in (
        "dataflow_timeout",
        "dataflow_slice_depth",
        "dataflow_file_filter",
        "dataflow_method_name_filter",
        "best_effort_dataflow",
    ):
        assert name in params


def test_e2e_script_has_independent_dataflow_controls():
    text = (
        Path(__file__).resolve().parents[1] / "scripts" / "joern_e2e.sh"
    ).read_text()
    assert "EVIDENCELAB_E2E_DATAFLOW_TIMEOUT" in text
    assert "EVIDENCELAB_E2E_SLICE_DEPTH" in text
    assert "PASS_WITH_WARNINGS" in text
    assert "EVIDENCELAB_E2E_STRICT" in text
