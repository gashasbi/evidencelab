from __future__ import annotations
import os, subprocess, sys, tomllib
import re


def test_python_version_is_supported():
    assert sys.version_info >= (3, 11)


def test_package_import_and_version(repo_root):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    p = subprocess.run(
        [sys.executable, "-c", "import evidencelab; print(evidencelab.__version__)"],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip()


def test_module_version_cli(repo_root):
    p = subprocess.run(
        [sys.executable, "-m", "evidencelab", "--version"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert p.returncode == 0, p.stderr
    assert "evidencelab" in p.stdout.lower()


def test_project_metadata_and_runtime_floor(repo_root):
    data = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["name"] == "evidencelab"
    assert project["requires-python"].startswith(">=")
    dev_dependencies = project.get("optional-dependencies", {}).get("dev", [])
    assert any(
        re.match(r"^pytest(?:[<>=!~;\[]|$)", dependency, re.IGNORECASE)
        for dependency in dev_dependencies
    ), f"pytest not found in dev dependencies: {dev_dependencies}"


def test_critical_source_files_exist(repo_root):
    for relative in (
        "evidencelab/__init__.py",
        "evidencelab/__main__.py",
        "evidencelab/cli.py",
        "evidencelab/matcher.py",
        "evidencelab/parsers.py",
        "evidencelab/semantics.py",
        "evidencelab/canonical.py",
        "evidencelab/witness_replay.py",
        "scripts/run_isolated_tests.py",
    ):
        assert (repo_root / relative).is_file(), relative
