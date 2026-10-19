from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil

import pytest

from evidencelab.capture import _sha256_path
from evidencelab.errors import EvidenceLabError


def test_file_hash_remains_sha256_of_file_bytes(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_bytes(b"int main(void) { return 0; }\n")

    assert _sha256_path(source) == hashlib.sha256(source.read_bytes()).hexdigest()


def test_directory_hash_is_stable_and_tracks_nested_file_content(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (source / "nested" / "helper.c").write_text(
        "int helper(void) { return 1; }\n", encoding="utf-8"
    )

    initial = _sha256_path(source)
    assert _sha256_path(source) == initial

    # Moving an identical tree must not change its digest; absolute paths are excluded.
    copied = tmp_path / "copied-source"
    shutil.copytree(source, copied)
    assert _sha256_path(copied) == initial

    (source / "nested" / "helper.c").write_text(
        "int helper(void) { return 2; }\n", encoding="utf-8"
    )
    assert _sha256_path(source) != initial


def test_directory_hash_ignores_file_mtime(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    file = source / "main.c"
    file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    initial = _sha256_path(source)

    os.utime(file, (1_600_000_000, 1_600_000_000))

    assert _sha256_path(source) == initial


def test_non_file_non_directory_source_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "missing.c"

    with pytest.raises(EvidenceLabError, match="not a regular file or directory"):
        _sha256_path(missing)


def test_directory_walk_errors_are_not_silently_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()

    def failing_walk(_path, *, followlinks=False, onerror=None):
        assert followlinks is False
        assert onerror is not None
        onerror(PermissionError("cannot scan directory"))
        return iter(())

    monkeypatch.setattr("evidencelab.capture.os.walk", failing_walk)

    with pytest.raises(
        EvidenceLabError, match="unable to hash source directory"
    ):
        _sha256_path(source)
