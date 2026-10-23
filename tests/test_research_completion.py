from pathlib import Path
import json, shutil, tempfile, os

ROOT = Path(__file__).resolve().parents[1]


def test_quality_excludes_mutation_descendants_from_independent_counts(tmp_path):
    from evidencelab.benchmark_quality import quality_audit

    m = tmp_path / "b.json"
    cases = [
        {"id": "p", "expected": "MATCH"},
        {"id": "n", "expected": "NO_MATCH"},
        {"id": "u", "expected": "UNKNOWN"},
        {
            "id": "pm",
            "expected": "MATCH",
            "mutation_of": "p",
            "changed_dimension": "extent",
        },
    ]
    m.write_text(
        json.dumps({"schema_version": "1.0", "manifest_id": "x", "cases": cases})
    )
    q = quality_audit(
        m, min_case_count=1, min_positive=2, min_negative=1, min_unknown=1
    )
    assert q["case_count"] == 4 and q["independent_case_count"] == 3
    assert q["independent_label_counts"]["MATCH"] == 1
    assert any("independent positive corpus too small" in e for e in q["errors"])


def test_pair_split_keeps_counterparts_together(tmp_path):
    from evidencelab.splits import split_benchmark, audit_split_directory

    m = tmp_path / "m.json"
    graphs = tmp_path / "graphs"
    graphs.mkdir()
    cases = []
    for i in range(6):
        before = f"b{i}"
        after = f"a{i}"
        cases += [
            {
                "id": before,
                "expected": "MATCH",
                "graph": f"graphs/{before}.json",
                "pair_id": f"pair{i}",
                "counterpart": after,
                "dataset": {
                    "repository": f"repo{i % 2}",
                    "commit": str(i),
                    "commit_date": f"202{i}-01-01",
                },
            },
            {
                "id": after,
                "expected": "NO_MATCH",
                "graph": f"graphs/{after}.json",
                "pair_id": f"pair{i}",
                "counterpart": before,
                "dataset": {
                    "repository": f"repo{i % 2}",
                    "commit": str(i) + "f",
                    "commit_date": f"202{i}-01-02",
                },
            },
        ]
        for j, x in enumerate((before, after)):
            (graphs / f"{x}.json").write_text(
                json.dumps(
                    {
                        "nodes": [{"id": x, "type": "X", "properties": {"n": j}}],
                        "edges": [],
                    }
                )
            )
    m.write_text(json.dumps({"manifest_id": "m", "cases": cases}))
    out = tmp_path / "split"
    r = split_benchmark(m, out, "repository", allow_missing_group=False)
    assert r["status"] == "PASS"
    ar = audit_split_directory(out, strategy="repository")
    assert ar["status"] == "PASS"


def test_hidden_requires_hmac_when_requested(tmp_path):
    from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle

    root = tmp_path / "src"
    (root / "graphs").mkdir(parents=True)
    g = root / "graphs" / "g.json"
    g.write_text(json.dumps({"nodes": [{"id": "1", "type": "X"}], "edges": []}))
    (root / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [
                    {
                        "id": "h",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                    }
                ],
            }
        )
    )
    b = tmp_path / "bundle"
    seal_hidden_benchmark(
        root / "benchmark.json",
        b,
        key="k",
        require_hmac=True,
        origin="external-evaluator",
    )
    assert (
        verify_hidden_bundle(b, "k", require_hmac=True, require_external_origin=True)[
            "status"
        ]
        == "PASS"
    )
    assert (
        verify_hidden_bundle(b, None, require_hmac=True, require_external_origin=True)[
            "status"
        ]
        == "FAIL"
    )


def test_hidden_redacts_source_metadata(tmp_path):
    from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle

    root = tmp_path / "src"
    (root / "graphs").mkdir(parents=True)
    (root / "graphs" / "g.json").write_text(json.dumps({"nodes": [], "edges": []}))
    (root / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [
                    {
                        "id": "h",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                        "source": "secret.c",
                        "source_metadata": {"secret": "x"},
                    }
                ],
            }
        )
    )
    b = tmp_path / "bundle"
    seal_hidden_benchmark(root / "benchmark.json", b, key="k", require_hmac=True)
    raw = json.loads((b / "benchmark.json").read_text())
    assert "source" not in raw["cases"][0] and "source_metadata" not in raw["cases"][0]
    assert verify_hidden_bundle(b, "k", require_hmac=True)["status"] == "PASS"


def test_realworld_import_has_hash_identity_and_label_provenance(tmp_path):
    from evidencelab.datasets import import_primevul_jsonl

    inp = tmp_path / "p.jsonl"
    out = tmp_path / "m.json"
    src = tmp_path / "src"
    inp.write_text(
        json.dumps(
            {
                "id": "x",
                "func": "int f(){return 1;}",
                "project": "o/r",
                "commit_id": "a" * 40,
                "target": 1,
                "cwe": "CWE-120",
                "CVE ID": "CVE-2024-1",
            }
        )
        + "\n"
    )
    import_primevul_jsonl(inp, out, src, cwe="CWE-120")
    c = json.loads(out.read_text())["cases"][0]
    assert c["label_provenance"]["authority"] == "DATASET"
    assert c["case_identity"]["source_sha256"]
    assert c["normalized_source_hash"]


def test_witness_validation_fails_on_expected_match_without_match(tmp_path):
    from evidencelab.witness_validator import validate_benchmark_matches

    p = ROOT / "examples/cwe-120/families/fixed-extent-overflow"
    raw = json.loads((p / "benchmark.json").read_text())

    safe = next(c for c in raw["cases"] if c["expected"] == "NO_MATCH")
    (tmp_path / "graphs").mkdir()
    source_graph = p / safe["graph"]
    shutil.copy2(source_graph, tmp_path / "graphs" / "safe.json")
    bench = {
        "schema_version": "1.0",
        "manifest_id": "bad",
        "cases": [{"id": "bad", "expected": "MATCH", "graph": "graphs/safe.json"}],
    }
    m = tmp_path / "b.json"
    m.write_text(json.dumps(bench))
    r = validate_benchmark_matches(
        m,
        __import__("evidencelab.spec", fromlist=["Pattern"]).Pattern.load(
            p / "pattern.json"
        ),
    )
    assert r["status"] == "FAIL"
    assert any("expected MATCH" in str(e) for e in r["errors"])


def test_research_readiness_command_reports_blockers(tmp_path, monkeypatch):
    import evidencelab.research_check as check
    from evidencelab.research_pipeline import research_readiness

    def fake_check(*args, **kwargs):
        return {
            "schema_version": "1.0",
            "tool_version": "1.0.0",
            "status": "FAIL",
            "family_count": 1,
            "families": [
                {
                    "family": "fixed-write",
                    "quality_audit": {
                        "errors": ["total cases below minimum: 40 < 200"]
                    },
                    "gate_errors": ["hidden validation is required"],
                }
            ],
            "pre_gate_errors": ["publication requires external hidden validation"],
        }

    monkeypatch.setattr(check, "run_research_check", fake_check)
    r = research_readiness(
        tmp_path, ROOT / "profiles/research-publication-c-cpp-joern.json"
    )
    assert r["status"] == "FAIL"
    assert r["blocking_conditions"]
    assert r["recommended_next_actions"]


def test_hidden_verify_rejects_extra_graph_artifact(tmp_path):
    from evidencelab.hidden import seal_hidden_benchmark, verify_hidden_bundle

    root = tmp_path / "src"
    (root / "graphs").mkdir(parents=True)
    (root / "graphs" / "g.json").write_text(
        json.dumps({"nodes": [{"id": "1", "type": "X"}], "edges": []})
    )
    (root / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [
                    {
                        "id": "h",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                    }
                ],
            }
        )
    )
    bundle = tmp_path / "hidden"
    seal_hidden_benchmark(
        root / "benchmark.json",
        bundle,
        key="k",
        require_hmac=True,
        origin="external-evaluator",
    )
    (bundle / "graphs" / "extra.json").write_text("{}")
    r = verify_hidden_bundle(
        bundle, "k", require_hmac=True, require_external_origin=True
    )
    assert r["status"] == "FAIL" and any(
        "unreferenced hidden graph" in x for x in r["errors"]
    )


def test_research_readiness_reports_unique_blockers(tmp_path, monkeypatch):
    import evidencelab.research_check as check
    from evidencelab.research_pipeline import research_readiness

    def fake_check(*args, **kwargs):
        return {
            "schema_version": "1.0",
            "tool_version": "1.0.0",
            "status": "FAIL",
            "family_count": 2,
            "families": [
                {
                    "family": "a",
                    "quality_audit": {"errors": ["total cases below minimum: 1 < 200"]},
                    "gate_errors": ["hidden validation is required"],
                },
                {
                    "family": "b",
                    "quality_audit": {"errors": ["total cases below minimum: 2 < 200"]},
                    "gate_errors": ["hidden validation is required"],
                },
            ],
            "pre_gate_errors": ["publication requires external hidden validation"],
        }

    monkeypatch.setattr(check, "run_research_check", fake_check)
    r = research_readiness(
        tmp_path, ROOT / "profiles/research-publication-c-cpp-joern.json"
    )
    assert r["status"] == "FAIL"
    assert r["unique_blocker_count"] <= r["blocking_condition_count"]
    assert r["blocker_counts_by_kind"]


def test_research_build_strict_split_fails_missing_metadata(tmp_path):
    from evidencelab.research_pipeline import build_external_research_corpus

    fam = ROOT / "examples/cwe-120/families/fixed-extent-overflow"
    raw = json.loads((fam / "benchmark.json").read_text())
    c = next(c for c in raw["cases"] if c.get("graph"))
    case = dict(c)
    case["id"] = "build-no-meta"
    case.pop("dataset", None)
    case.pop("source_manifest", None)
    gsrc = fam / case["graph"]
    (tmp_path / "graphs").mkdir()
    shutil.copy2(gsrc, tmp_path / "graphs" / "g.json")
    case["graph"] = "graphs/g.json"
    src = tmp_path / "input.json"
    src.write_text(
        json.dumps({"schema_version": "1.0", "manifest_id": "input", "cases": [case]})
    )
    r = build_external_research_corpus(
        [src], tmp_path / "out", capture=False, split=True
    )
    assert r["status"] == "FAIL"
    assert (
        r["repository_split"]["status"] == "FAIL"
        or r["chronological_split"]["status"] == "FAIL"
    )


def test_cli_hidden_seal_honors_security_flags(tmp_path, monkeypatch):
    import subprocess, sys

    root = tmp_path / "src"
    (root / "graphs").mkdir(parents=True)
    (root / "graphs" / "g.json").write_text(
        json.dumps({"nodes": [{"id": "1", "type": "X"}], "edges": []})
    )
    (root / "benchmark.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "manifest_id": "m",
                "cases": [
                    {
                        "id": "h",
                        "expected": "UNKNOWN",
                        "graph": "graphs/g.json",
                        "partition": "hidden",
                    }
                ],
            }
        )
    )
    out = tmp_path / "hidden"
    monkeypatch.setenv("EL_KEY", "cli-secret")
    cmd = [
        sys.executable,
        "-m",
        "evidencelab",
        "hidden-seal",
        "--benchmark",
        str(root / "benchmark.json"),
        "--out",
        str(out),
        "--key-env",
        "EL_KEY",
        "--require-hmac",
        "--origin",
        "external-evaluator",
    ]
    r = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    seal = json.loads((out / "seal.json").read_text())
    assert seal["hmac_required"] is True and seal["origin"] == "external-evaluator"
    cmd = [
        sys.executable,
        "-m",
        "evidencelab",
        "hidden-verify",
        "--bundle",
        str(out),
        "--key-env",
        "EL_KEY",
        "--require-hmac",
        "--require-external-origin",
    ]
    r = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    assert r.returncode == 0, r.stdout + r.stderr
    payload = json.loads(r.stdout)
    assert payload["hmac_required"] is True
