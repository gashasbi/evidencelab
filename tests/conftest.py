from __future__ import annotations
import os
from pathlib import Path
import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    raw = os.environ.get("EVIDENCELAB_REPO_ROOT")
    root = Path(raw).resolve() if raw else Path(__file__).resolve().parents[1]
    if not (root / "evidencelab").is_dir():
        pytest.fail(f"Not an EvidenceLab repository root: {root}")
    return root
