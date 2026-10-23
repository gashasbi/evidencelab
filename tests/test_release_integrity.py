from pathlib import Path
import json
import stat

ROOT = Path(__file__).resolve().parents[1]


def test_patterns_use_supported_schema():
    from evidencelab.spec import Pattern

    paths = list(ROOT.glob("examples/cwe-121/families/*/pattern.json")) + list(
        ROOT.glob("examples/cwe-120/families/*/pattern.json")
    )
    assert paths
    for p in paths:
        raw = json.loads(p.read_text())
        assert raw["schema_version"] == "1.0"
        Pattern.load(p)
    assert len(list((ROOT / "schemas").glob("*.schema.json"))) == 19
    assert not (ROOT / "legacy").exists()
    assert not list((ROOT / "schemas").rglob("*v[0-9]*.schema.json"))
    for p in ROOT.glob("examples/cwe-120/families/*/pattern.json"):
        assert json.loads(p.read_text())["schema_version"] == "1.0"


def test_all_corpus_graphs_parse_cleanly():
    from evidencelab.parsers import parse_graph

    for base in (
        ROOT / "examples/cwe-121/corpus/graphs",
        ROOT / "examples/cwe-120/corpus",
    ):
        graph_dir = base / "graphs" if (base / "graphs").exists() else base
        for p in graph_dir.glob("*.json"):
            g = parse_graph(p)
            assert g.metadata["parse_health"] in {"OK", "DEGRADED", "PARTIAL"}, p
            assert g.metadata["integrity"]["missing_edge_endpoints"] == 0


def test_cwe120_corpus_and_families_exist():
    fam = list((ROOT / "examples/cwe-120/families").glob("*/pattern.json"))
    src = list((ROOT / "examples/cwe-120/corpus/source").glob("*.c"))
    assert len(fam) == 6
    assert len(src) >= 12


def test_source_corpus_exists():
    files = list((ROOT / "examples/cwe-121/corpus/source").glob("*.c"))
    assert len(files) >= 7


def test_versions_are_consistent():
    import evidencelab

    pyproject = (ROOT / "pyproject.toml").read_text()
    build = json.loads((ROOT / "BUILD-INFO.json").read_text())
    readme = (ROOT / "README.md").read_text().splitlines()[0]
    assert f'version = "{evidencelab.__version__}"' in pyproject
    assert build["version"] == evidencelab.__version__
    assert readme == f"# EvidenceLab {evidencelab.__version__}"
    assert evidencelab.SCHEMA_VERSION == "1.0"


def test_release_metadata_has_no_cache_directories():

    assert not (ROOT / "dist").exists() or not any(
        part in {".pytest_cache", "__pycache__"}
        for path in (ROOT / "dist").rglob("*")
        for part in path.parts
    )


def test_scripts_are_executable():
    for p in (ROOT / "scripts").glob("*.sh"):
        assert p.stat().st_mode & stat.S_IXUSR, p


def test_release_maturity_metadata_is_consistent():
    import json
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    build_info = json.loads((ROOT / "BUILD-INFO.json").read_text(encoding="utf-8"))

    maturity = [
        item
        for item in pyproject["project"]["classifiers"]
        if item.startswith("Development Status :: ")
    ]

    assert maturity == ["Development Status :: 4 - Beta"]
    assert build_info["release_type"] == "beta_public_release"
