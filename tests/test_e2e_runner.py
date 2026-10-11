from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_joern_e2e_script_has_independent_case_timeout():
    s = (ROOT / "scripts" / "joern_e2e.sh").read_text()
    assert "EVIDENCELAB_E2E_CASE_TIMEOUT" in s
    assert "No global timeout is imposed" in s
    assert "e2e-report.json" in s
    assert "timeout=case_timeout" in s
