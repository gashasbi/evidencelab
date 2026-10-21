from pathlib import Path
import json, tempfile

from evidencelab.project import init_research_project, append_experiment
from evidencelab.experiment import audit_experiment_ledger
from evidencelab.provenance import build_provenance_manifest, verify_artifact_manifest
from evidencelab.leakage import audit_source_files
from evidencelab.splits import split_benchmark, chronological_split
from evidencelab.benchmark_quality import quality_audit
from evidencelab.datasets import import_sard_table, import_primevul_jsonl
from evidencelab.sarif_ingest import sarif_to_graph

ROOT = Path(__file__).resolve().parents[1]


def test_research_workspace_and_chained_experiments():
    with tempfile.TemporaryDirectory() as td:
        root = init_research_project("CWE-120", Path(td) / "research")
        assert (root / "task.json").is_file()
        append_experiment(
            root,
            {
                "experiment_id": "E1",
                "hypothesis": "h",
                "tool": "Joern",
                "command": "joern --help",
                "result": "pass",
            },
        )
        assert audit_experiment_ledger(root)["status"] == "PASS"
        assert (root / "experiments" / "experiment-log.jsonl").read_text().strip()


def test_provenance_manifest_round_trip():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.txt").write_text("a", encoding="utf-8")
        manifest = root / "prov.json"
        build_provenance_manifest(root, out=manifest)
        assert verify_artifact_manifest(manifest)["status"] == "PASS"
        (root / "a.txt").write_text("tampered", encoding="utf-8")
        assert verify_artifact_manifest(manifest)["status"] == "FAIL"


def test_leakage_detects_exact_duplicate():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = root / "a.c"
        b = root / "b.c"
        text = "int f(){char b[32]; return b[0];}\n"
        a.write_text(text)
        b.write_text(text)
        result = audit_source_files([a, b])
        assert result["status"] == "WARN"
        assert result["exact_duplicate_groups"]


def test_split_keeps_repository_groups_separate():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        m = root / "m.json"
        cases = []
        for i in range(12):
            cases.append(
                {
                    "id": str(i),
                    "expected": "MATCH"
                    if i % 3 == 0
                    else ("NO_MATCH" if i % 3 == 1 else "UNKNOWN"),
                    "graph": f"g{i}.json",
                    "dataset": {"repository": f"repo{i // 2}"},
                    "tags": ["positive" if i % 3 == 0 else "negative"],
                }
            )
        m.write_text(json.dumps({"manifest_id": "m", "cases": cases}), encoding="utf-8")
        out = root / "split"
        r = split_benchmark(m, out, strategy="repository")
        assert r["status"] == "PASS"
        owners = {}
        for name in ("train", "validation", "test"):
            data = json.loads((out / f"{name}.json").read_text())
            for c in data["cases"]:
                repo = c["dataset"]["repository"]
                assert repo not in owners or owners[repo] == name
                owners[repo] = name


def test_chronological_split():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        m = root / "m.json"
        cases = [
            {
                "id": str(i),
                "expected": "MATCH",
                "graph": f"g{i}.json",
                "date": f"202{i}-01-01",
            }
            for i in range(10)
        ]
        m.write_text(json.dumps({"manifest_id": "m", "cases": cases}), encoding="utf-8")
        r = chronological_split(m, root / "s", train=0.6, validation=0.2)
        assert r["status"] == "PASS" and r["counts"] == {
            "train": 6,
            "validation": 2,
            "test": 2,
        }


def test_sarif_ingest_builds_observation_graph():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "r.sarif"
        p.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "X"}},
                            "results": [
                                {
                                    "ruleId": "CWE-120",
                                    "level": "warning",
                                    "message": {"text": "x"},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": "a.c"},
                                                "region": {"startLine": 4},
                                            }
                                        }
                                    ],
                                    "codeFlows": [
                                        {
                                            "threadFlows": [
                                                {
                                                    "locations": [
                                                        {
                                                            "location": {
                                                                "physicalLocation": {
                                                                    "artifactLocation": {
                                                                        "uri": "a.c"
                                                                    },
                                                                    "region": {
                                                                        "startLine": 1
                                                                    },
                                                                }
                                                            }
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        g = sarif_to_graph(p)
        assert len(g.nodes) >= 3 and len(g.edges) >= 2


def test_sard_and_primevul_importers():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        csvp = root / "sard.csv"
        csvp.write_text(
            "id,cwe,state,source\n1,CWE-120,bad,a.c\n2,CWE-120,good,b.c\n",
            encoding="utf-8",
        )
        sard = import_sard_table(csvp, root / "sard.json", source_root=root)
        assert sard["case_count"] == 2
        prime = root / "prime.jsonl"
        prime.write_text(
            json.dumps(
                {
                    "func": "int f(){return 0;}",
                    "project": "p",
                    "commit_id": "c",
                    "target": 0,
                    "cwe": "CWE-120",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        pv = import_primevul_jsonl(
            prime, root / "prime-manifest.json", root / "prime-src", cwe="CWE-120"
        )
        assert pv["case_count"] == 1 and (root / "prime-src").is_dir()


def test_secvuleval_importer_preserves_real_world_metadata():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "sec.jsonl"
        src.write_text(
            json.dumps(
                {
                    "function_code": "int f(void){return 1;}",
                    "target": 1,
                    "project": "org/repo",
                    "commit": "abc123",
                    "CVE": "CVE-2026-0001",
                    "file_path": "src/a.c",
                    "patch_diff": "- old\\n+ new",
                    "date": "2026-01-02T00:00:00Z",
                    "cwe": "CWE-120",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        result = __import__(
            "evidencelab.datasets", fromlist=["import_secvuleval_jsonl"]
        ).import_secvuleval_jsonl(
            src, root / "out.json", root / "source", cwe="CWE-120"
        )
        assert result["case_count"] == 1
        case = json.loads((root / "out.json").read_text(encoding="utf-8"))["cases"][0]
        assert case["expected"] == "MATCH"
        assert case["dataset"]["repository"] == "org/repo"
        assert case["dataset"]["cve"] == "CVE-2026-0001"
        assert case["dimensions"] and "real_world" in case["dimensions"]
        assert "source_metadata" in case


def test_juliet_import_defaults_to_unknown_label():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "CWE120_Buffer_Copy.c"
        src.write_text("void bad(void){}\nvoid good(void){}\n", encoding="utf-8")
        from evidencelab.datasets import import_juliet

        r = import_juliet(root, root / "m.json", cwe="CWE-120")
        assert r["case_count"] == 1
        case = json.loads((root / "m.json").read_text(encoding="utf-8"))["cases"][0]
        assert case["expected"] == "UNKNOWN"
        assert case["dataset"]["label_source"].startswith("not assigned")


def test_family_init_creates_current_family_scaffold():
    with tempfile.TemporaryDirectory() as td:
        root = init_research_project("CWE-120", Path(td) / "research")
        from evidencelab.family import init_evidence_family

        fam = init_evidence_family(
            root,
            "guard-aware",
            research_question="Can guard dominance refute the witness?",
        )
        assert (fam / "pattern.json").is_file()
        assert (fam / "benchmark.json").is_file()
        raw = json.loads((fam / "pattern.json").read_text(encoding="utf-8"))
        assert raw["schema_version"] == "1.0"
        assert (fam / "tests/unknown").is_dir()


def test_schema_check_validates_pattern_and_rejects_wrong_schema():
    import os, subprocess, sys

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    good = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidencelab",
            "schema-check",
            "--input",
            str(ROOT / "examples/cwe-120/families/fixed-extent-overflow/pattern.json"),
            "--schema",
            str(ROOT / "schemas/evidence-pattern.schema.json"),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert good.returncode == 0, good.stdout + good.stderr
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "bad.json"
        raw = json.loads(
            (
                ROOT / "examples/cwe-120/families/fixed-extent-overflow/pattern.json"
            ).read_text()
        )
        raw["schema_version"] = "unsupported-schema"
        bad.write_text(json.dumps(raw), encoding="utf-8")
        bad_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidencelab",
                "schema-check",
                "--input",
                str(bad),
                "--schema",
                str(ROOT / "schemas/evidence-pattern.schema.json"),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        assert bad_run.returncode == 1, bad_run.stdout + bad_run.stderr


def test_cluster_groups_do_not_create_singletons_for_missing_provenance():
    from evidencelab.statistics import _cluster_groups

    unknown_a = {"id": "unique-a"}
    unknown_b = {"id": "unique-b"}
    repo_a = {"id": "repo-a-1", "dataset": {"repository": "repo-a"}}
    repo_b = {"id": "repo-a-2", "dataset": {"repository": "repo-a"}}

    groups = _cluster_groups([unknown_a, unknown_b, repo_a, repo_b])

    assert len(groups) == 1
    assert set(id(case) for case in groups[0]) == {id(repo_a), id(repo_b)}


def test_cluster_bootstrap_mean_rejects_missing_cluster_identity():
    from evidencelab.statistics import cluster_bootstrap_mean

    result = cluster_bootstrap_mean([(None, 1.0), ("", 0.0)], rounds=100)

    assert result["status"] == "UNAVAILABLE_MISSING_CLUSTER_ID"
    assert result["clusters"] == 0
    assert result["unclustered_cases"] == 2
    assert result["ci95"] == [None, None]


def test_cluster_bootstrap_mean_requires_two_identified_clusters():
    from evidencelab.statistics import cluster_bootstrap_mean

    one = cluster_bootstrap_mean(
        [("repository:repo-a", 1.0), ("repository:repo-a", 0.0)],
        rounds=100,
    )
    assert one["status"] == "UNAVAILABLE_INSUFFICIENT_CLUSTERS"
    assert one["clusters"] == 1
    assert one["ci95"] == [None, None]

    two = cluster_bootstrap_mean(
        [
            ("repository:repo-a", 1.0),
            ("repository:repo-a", 1.0),
            ("repository:repo-b", 0.0),
            ("repository:repo-b", 0.0),
        ],
        rounds=100,
    )
    assert two["status"] == "PASS"
    assert two["clusters"] == 2


def test_binary_cluster_bootstrap_does_not_use_case_ids_as_clusters():
    from evidencelab.statistics import cluster_bootstrap_binary_metrics

    result = cluster_bootstrap_binary_metrics(
        [
            {"case_id": "unique-a", "expected": "MATCH", "actual": "MATCH"},
            {"case_id": "unique-b", "expected": "NO_MATCH", "actual": "NO_MATCH"},
        ],
        rounds=100,
    )

    assert result["status"] == "UNAVAILABLE_MISSING_CLUSTER_ID"
    assert result["clusters"] == 0
    assert result["unclustered_cases"] == 2
    assert all(ci == [None, None] for ci in result["ci95"].values())


def test_binary_cluster_bootstrap_requires_two_identified_clusters():
    from evidencelab.statistics import cluster_bootstrap_binary_metrics

    rows = [
        {
            "case_id": "positive",
            "repository": "repo-a",
            "expected": "MATCH",
            "actual": "MATCH",
        },
        {
            "case_id": "negative",
            "repository": "repo-b",
            "expected": "NO_MATCH",
            "actual": "NO_MATCH",
        },
    ]
    result = cluster_bootstrap_binary_metrics(rows, rounds=100)

    assert result["status"] == "PASS"
    assert result["clusters"] == 2
    assert result["unclustered_cases"] == 0
    assert "false_negative_rate" in result["ci95"]

    same_cluster = [
        {**rows[0], "repository": "repo-a"},
        {**rows[1], "repository": "repo-a"},
    ]
    unavailable = cluster_bootstrap_binary_metrics(same_cluster, rounds=100)
    assert unavailable["status"] == "UNAVAILABLE_INSUFFICIENT_CLUSTERS"
    assert unavailable["clusters"] == 1


def test_profile_gate_rejects_unavailable_cluster_statistics():
    from evidencelab.profile import validate_benchmark_gate

    errors = validate_benchmark_gate(
        metrics={
            "total": 2,
            "known": 2,
            "tp": 1,
            "fn": 0,
            "tn": 1,
            "fp": 0,
        },
        meta={
            "cluster_statistics": {
                "classification": {
                    "status": "UNAVAILABLE_MISSING_CLUSTER_ID",
                    "clusters": 0,
                    "ci95": {"recall": [None, None]},
                }
            }
        },
        profile={"require_cluster_aware_statistics": True},
    )

    assert any(
        "cluster-aware statistics require at least two identified clusters"
        in error
        for error in errors
    )



def test_repository_split_balances_unequal_group_sizes_and_reports_quality(tmp_path):
    from evidencelab.splits import audit_split_directory

    manifest = tmp_path / "unequal-repositories.json"
    out = tmp_path / "split"

    cases = []
    group_sizes = {
        "large-train-candidate": 45,
        "large-test-candidate": 22,
        "small-a": 3,
        "small-b": 3,
        "small-c": 2,
    }

    for repository, size in group_sizes.items():
        for index in range(size):
            cases.append({
                "id": f"{repository}-{index}",
                "expected": "MATCH" if index % 2 == 0 else "NO_MATCH",
                "dataset": {"repository": repository},
            })

    manifest.write_text(
        json.dumps({
            "schema_version": "1.0",
            "format": "evidencelab-benchmark",
            "manifest_id": "unequal-repository-split-regression",
            "cases": cases,
        }),
        encoding="utf-8",
    )

    split = split_benchmark(
        manifest,
        out,
        strategy="repository",
        train=0.6,
        validation=0.2,
        test=0.2,
    )

    assert split["status"] == "PASS"
    assert sorted(split["counts"].values()) == [8, 22, 45]
    assert split["counts"] == {"train": 45, "validation": 22, "test": 8}
    assert split["partition_group_counts"] == {
        "train": 1,
        "validation": 1,
        "test": 3,
    }
    assert split["partition_case_ratios"]["train"] == 0.6
    assert any(
        "validation partition has fewer than two indivisible groups" in warning
        for warning in split["quality_warnings"]
    )
    assert any(
        "test case ratio differs materially from its target" in warning
        and "relative deviation=46.7%" in warning
        for warning in split["quality_warnings"]
    )

    audit = audit_split_directory(out, strategy="repository")
    assert audit["status"] == "PASS"
    assert not audit["errors"]

    summary = audit["partition_summary"]
    assert summary["train"]["case_count"] == 45
    assert summary["train"]["identified_groups"] == 1
    assert summary["validation"]["case_count"] == 22
    assert summary["validation"]["identified_groups"] == 1
    assert summary["test"]["case_count"] == 8
    assert summary["test"]["identified_groups"] == 3

    assert any(
        "validation partition has fewer than two identified repository groups"
        in warning
        for warning in audit["quality_warnings"]
    )
