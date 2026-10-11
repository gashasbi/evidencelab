import json
from pathlib import Path

from evidencelab.contract import research_tree_inventory, bundle_research_package
from evidencelab.audit import audit_pattern
from evidencelab.benchmark_quality import quality_audit
from evidencelab.spec import Pattern
from evidencelab.datasets import import_diversevul_jsonl

ROOT = Path(__file__).resolve().parents[1]


def test_public_reference_stays_below_strict_gate_without_real_data():
    profile = json.loads(
        (ROOT / "profiles/research-publication-c-cpp-joern.json").read_text()
    )
    families = sorted((ROOT / "examples/cwe-120/families").glob("*/pattern.json"))
    assert len(families) == 6
    for pattern_path in families:
        pattern = Pattern.load(pattern_path)
        findings = audit_pattern(pattern)
        assert not [x for x in findings if x.severity == "ERROR"], [
            x.to_dict() for x in findings
        ]
        gates = profile["gates"]
        quality = quality_audit(
            pattern_path.parent / "benchmark.json",
            min_case_count=gates["min_total"],
            min_positive=gates["min_positive"],
            min_negative=gates["min_negative"],
            min_unknown=gates["min_unknown"],
            min_real_world=profile["min_real_world_cases"],
            required_dimensions=set(profile["required_dimensions"]),
            dimension_minima=profile["dimension_minima"],
            min_dataset_sources=profile["min_dataset_sources"],
            min_repositories=profile["min_repositories"],
            min_projects=profile["min_projects"],
            min_cves=profile["min_cves"],
            require_split_strategies=set(profile["required_split_strategies"]),
            require_label_provenance=profile["require_label_provenance"],
            require_case_identity=profile["require_case_identity"],
            min_real_world_label_authority=profile["min_real_world_label_authority"],
        )
        assert quality["status"] == "FAIL"
        assert quality["case_count"] < gates["min_total"]


def test_inventory_excludes_external_raw_data_by_default(tmp_path):
    (tmp_path / "datasets/raw").mkdir(parents=True)
    (tmp_path / "datasets/raw" / "huge.txt").write_text("raw")
    (tmp_path / "README.md").write_text("x")
    r = research_tree_inventory(tmp_path)
    assert all("datasets/raw" not in x["path"] for x in r["artifacts"])


def test_diversevul_importer_preserves_dataset_target_and_identity(tmp_path):
    inp = tmp_path / "d.jsonl"
    inp.write_text(
        json.dumps(
            {
                "idx": 1,
                "target": 1,
                "project": "org/repo",
                "commit_id": "a" * 40,
                "commit_date": "2024-01-02T00:00:00Z",
                "cwe": ["CWE-120"],
                "file_name": "x.c",
                "func": "int x(){return 0;}",
            }
        )
        + "\n"
    )
    out = tmp_path / "manifest.json"
    r = import_diversevul_jsonl(inp, out, tmp_path, cwe="CWE-120")
    assert r["case_count"] == 1
    case = json.loads(out.read_text())["cases"][0]
    assert case["expected"] == "MATCH"
    assert case["label_provenance"]["authority"] == "DATASET"
    assert case["dataset"]["commit"] == "a" * 40


def test_evaluation_schemas_exist():
    for name in ("evaluation-case.schema.json", "evaluation.schema.json"):
        assert (ROOT / "schemas" / name).is_file()


def test_matcher_does_not_mutate_graph_digest_and_stored_witness_replays(tmp_path):
    from evidencelab.parsers import parse_graph
    from evidencelab.spec import Pattern
    from evidencelab.matcher import Matcher
    from evidencelab.research_evaluation import (
        evaluate_benchmark,
        replay_stored_directory,
    )

    p = ROOT / "examples/cwe-120/families/fixed-extent-overflow"
    graph_path = next((p / "graphs").glob("*.json"))
    graph = parse_graph(graph_path)
    before = graph.digest()
    pattern = Pattern.load(p / "pattern.json")
    result = Matcher(graph).run(pattern)
    assert graph.digest() == before
    assert result.evidence_trace["graph_digest"] == before
    out = tmp_path / "evaluation"
    summary = evaluate_benchmark(
        p / "benchmark.json", p / "pattern.json", out, replay=True
    )
    assert summary["independent_replay"]["status"] == "PASS", summary[
        "independent_replay"
    ]
    replay = replay_stored_directory(out, p / "pattern.json")
    assert replay["status"] == "PASS", replay


def test_split_artifacts_are_portable_and_auditable(tmp_path):
    from evidencelab.splits import (
        split_benchmark,
        chronological_split,
        audit_split_directory,
    )
    import json, shutil

    source = tmp_path / "source-benchmark.json"
    raw = json.loads(
        (
            ROOT / "examples/cwe-120/families/fixed-extent-overflow/benchmark.json"
        ).read_text()
    )
    for idx, case in enumerate(raw["cases"]):
        case["dataset"] = {
            "repository": f"org/repo-{idx % 8}",
            "project": f"project-{idx % 8}",
            "commit": f"{idx:040d}",
            "commit_date": f"2020-01-{(idx % 28) + 1:02d}",
        }
        src_graph = (
            ROOT / "examples/cwe-120/families/fixed-extent-overflow" / case["graph"]
        )
        import shutil

        (tmp_path / "graphs").mkdir(exist_ok=True)
        shutil.copy2(src_graph, tmp_path / "graphs" / src_graph.name)
        case["graph"] = str(
            (tmp_path / "graphs" / src_graph.name).relative_to(tmp_path)
        )
    source.write_text(json.dumps(raw), encoding="utf-8")
    repo = tmp_path / "repo-split"
    chrono = tmp_path / "chrono-split"
    r1 = split_benchmark(source, repo, strategy="repository")
    assert r1["status"] == "PASS", r1
    chrono_source = tmp_path / "chrono-source.json"
    chrono_raw = json.loads(source.read_text())
    for idx, case in enumerate(chrono_raw["cases"]):
        case.pop("mutation_of", None)
        case.pop("changed_dimension", None)
        case["date"] = f"2020-{(idx // 28) + 1:02d}-{(idx % 28) + 1:02d}"
    chrono_source.write_text(json.dumps(chrono_raw), encoding="utf-8")
    r2 = chronological_split(chrono_source, chrono)
    assert r2["status"] == "PASS", r2
    a1 = audit_split_directory(repo, strategy="repository")
    assert a1["status"] == "PASS", a1
    a2 = audit_split_directory(chrono, strategy=None)
    assert a2["status"] == "PASS", a2
    sample = json.loads((repo / "train.json").read_text())
    assert sample["split"]["graph_materialization"] == "copied"
    assert all(str(c["graph"]).startswith("graphs/") for c in sample["cases"])
    assert (repo / "graphs").is_dir()


def test_split_manifest_can_be_evaluated_after_moving_split_directory(tmp_path):
    from evidencelab.splits import split_benchmark
    from evidencelab.evaluator import run_manifest
    from evidencelab.spec import Pattern
    import json, shutil

    source = tmp_path / "source-benchmark.json"
    raw = json.loads(
        (
            ROOT / "examples/cwe-120/families/fixed-extent-overflow/benchmark.json"
        ).read_text()
    )
    for idx, case in enumerate(raw["cases"]):
        case["dataset"] = {
            "repository": f"org/repo-{idx % 8}",
            "project": f"project-{idx % 8}",
            "commit": f"{idx:040d}",
            "commit_date": f"2020-01-{(idx % 28) + 1:02d}",
        }
        src_graph = (
            ROOT / "examples/cwe-120/families/fixed-extent-overflow" / case["graph"]
        )
        import shutil

        (tmp_path / "graphs").mkdir(exist_ok=True)
        shutil.copy2(src_graph, tmp_path / "graphs" / src_graph.name)
        case["graph"] = str(
            (tmp_path / "graphs" / src_graph.name).relative_to(tmp_path)
        )
    source.write_text(json.dumps(raw), encoding="utf-8")
    out = tmp_path / "split"
    split_benchmark(source, out, strategy="repository")
    moved = tmp_path / "moved"
    shutil.copytree(out, moved)
    p = Pattern.load(
        ROOT / "examples/cwe-120/families/fixed-extent-overflow/pattern.json"
    )
    results, metrics, _ = run_manifest(moved / "test.json", p, reveal=False)
    assert results
    assert metrics.total == len(results)
