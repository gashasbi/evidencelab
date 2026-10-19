from __future__ import annotations
import os
from pathlib import Path
import pytest

@pytest.fixture(scope="session")
def repo_root() -> Path:
    raw = os.environ.get("EVIDENCELAB_REPO_ROOT")
    if not raw:
        pytest.fail("EVIDENCELAB_REPO_ROOT was not set by run_quality_suite.py")
    root = Path(raw).resolve()
    if not (root / "evidencelab").is_dir():
        pytest.fail(f"Not an EvidenceLab repository root: {root}")
    return root
