from __future__ import annotations
import json
from pathlib import Path
import json as _json
import tempfile
from typing import Any
from . import SCHEMA_VERSION
from .audit import audit_pattern
from .evaluator import audit_benchmark_manifest, run_manifest, compare_manifests
from .profile import load_profile, validate_benchmark_gate
from .spec import Pattern
from .research_package import discover_families, audit_research_package
from .benchmark_quality import quality_audit
from .witness_validator import validate_match_result, validate_benchmark_matches
from .witness_replay import WitnessReplay
from .evidence_quality import compute_evidence_quality
from .hidden import verify_hidden_bundle
from .parsers import parse_graph
from .contract import audit_no_placeholders
from .research_records import audit_research_ledgers
from .statistics import cluster_bootstrap_mean, cluster_bootstrap_binary_metrics
from .failure_taxonomy import classify_errors, taxonomy_payload
from .performance import profile_pattern


def _family_graph_for_validation(benchmark: Path) -> Path | None:
    raw = json.loads(benchmark.read_text(encoding="utf-8"))
    for c in raw.get("cases", []):
        if str(c.get("partition", "public")) == "public" and c.get("graph"):
            gp = (benchmark.parent / str(c["graph"])).resolve()
            if gp.is_file():
                return gp
    return None


def _find_split_dir(root: Path, family: Path, strategy: str) -> Path | None:
    candidates = [
        family / "splits" / strategy,
        family / "benchmark-splits" / strategy,
        root / "splits" / strategy,
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def _stored_replay_for_results(
    benchmark: Path, pattern: Pattern, results: list[Any]
) -> dict[str, Any]:
    """Serialize matcher results to temporary case reports, then replay fixed bindings.

    This deliberately does not run Matcher again. It tests the boundary between discovery
    and validation, including JSON round-trip fidelity.
    """
    raw = _json.loads(benchmark.read_text(encoding="utf-8"))
    case_map = {
        str(c.get("id")): c for c in raw.get("cases", []) if isinstance(c, dict)
    }
    passed = 0
    selected = 0
    errors = []
    with tempfile.TemporaryDirectory(prefix="evidencelab-stored-replay-") as td:
        for result in results:
            if str(getattr(result, "actual", "UNKNOWN")).upper() != "MATCH":
                continue
            case = case_map.get(result.case_id) or {}
            graph_ref = case.get("graph")
            if not graph_ref:
                errors.append(
                    {"id": result.case_id, "errors": ["case has no graph path"]}
                )
                continue
            graph = (benchmark.parent / str(graph_ref)).resolve()
            report = {
                "schema_version": SCHEMA_VERSION,
                "format": "evidencelab-evaluation-case",
                "case_id": result.case_id,
                "actual": result.actual,
                "expected": result.expected,
                "graph": str(graph),
                "graph_digest": result.graph_digest,
                "pattern": str(pattern.source_path or ""),
                "pattern_sha256": __import__(
                    "evidencelab.provenance", fromlist=["sha256_file"]
                ).sha256_file(Path(pattern.source_path))
                if pattern.source_path
                else None,
                "matcher": result.detail,
            }
            path = Path(td) / (result.case_id + ".json")
            path.write_text(_json.dumps(report, ensure_ascii=False), encoding="utf-8")
            selected += 1
            try:
                replay = __import__(
                    "evidencelab.witness_validator", fromlist=["replay_stored_report"]
                ).replay_stored_report(
                    _json.loads(path.read_text(encoding="utf-8")), graph, pattern
                )
            except Exception as exc:
                replay = {"status": "FAIL", "errors": [str(exc)]}
            if replay.get("status") == "PASS":
                passed += 1
            else:
                errors.append({"id": result.case_id, **replay})
    return {
        "status": "PASS" if not errors else "FAIL",
        "selected_cases": selected,
        "passed_cases": passed,
        "failed_cases": len(errors),
        "errors": errors[:100],
        "validation_mode": "serialized-fixed-binding-semantic-replay",
    }


def run_research_check(
    root: str | Path,
    profile_path: str | Path | None = None,
    hidden_root: str | Path | None = None,
    enforce_gates: bool = False,
    require_hidden: bool = False,
    hidden_key_env: str | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve()
    profile = load_profile(profile_path) if profile_path else {}
    families = discover_families(root)
    if not families:
        raise ValueError(f"no Evidence Families found under {root}")
    placeholder_audit = audit_no_placeholders(root, allow_scaffold=True)
    ledger_audit = audit_research_ledgers(
        root, require_nonempty=bool(profile.get("require_research_ledgers", False))
    )
    pre_gate_errors: list[str] = []
    if (
        enforce_gates
        and profile.get("require_research_ledgers", False)
        and ledger_audit.get("status") != "PASS"
    ):
        pre_gate_errors.extend(str(x) for x in ledger_audit.get("errors", []))
    if (
        enforce_gates
        and profile.get("require_no_placeholders", False)
        and placeholder_audit.get("status") != "PASS"
    ):
        errors_placeholder = placeholder_audit.get("placeholders", [])
        if placeholder_audit.get("status") == "SCAFFOLD":
            pre_gate_errors.append(
                "research package is only a scaffold; an executable Evidence Family is required"
            )
        else:
            pre_gate_errors.append(
                f"unfinished Evidence Family placeholders detected: {len(errors_placeholder)}"
            )
    hidden_base = Path(hidden_root).resolve() if hidden_root else None
    hidden_integrity = None
    hidden_policy = (profile.get("hidden_policy") or {}) if profile else {}
    if hidden_base and hidden_policy.get("forbid_hidden_under_public_root", False):
        try:
            hidden_base.relative_to(root)
            pre_gate_errors.append(
                "hidden validation bundle must be outside the public research root"
            )
        except ValueError:
            pass
    if hidden_base:
        import os

        require_sealed_hidden = bool(
            require_hidden
            or profile.get("require_hidden_validation", False)
            or profile.get("require_hidden_hmac", False)
            or hidden_policy.get("require_external_origin", False)
        )
        seal_path = hidden_base / "seal.json"
        if seal_path.is_file():
            hidden_key = os.environ.get(hidden_key_env) if hidden_key_env else None
            hidden_integrity = verify_hidden_bundle(
                hidden_base,
                hidden_key,
                require_hmac=bool(profile.get("require_hidden_hmac", False)),
                require_external_origin=bool(
                    hidden_policy.get("require_external_origin", False)
                ),
            )
        elif require_sealed_hidden:
            pre_gate_errors.append("hidden validation bundle must contain seal.json")
    results = []
    errors = len(pre_gate_errors)
    aggregate = {
        k: 0
        for k in (
            "total",
            "known",
            "tp",
            "fp",
            "tn",
            "fn",
            "expected_unknown",
            "actual_unknown",
            "unknown_correct",
            "unknown_wrong",
            "overclaims",
        )
    }
    for family in families:
        pattern = Pattern.load(family / "pattern.json")
        findings = audit_pattern(pattern, profile.get("audit", {})) if profile else []
        audit_errors = [x.to_dict() for x in findings if x.severity == "ERROR"]
        item = {
            "family": family.name,
            "pattern": str((family / "pattern.json").relative_to(root)),
            "pattern_audit": {
                "status": "FAIL" if audit_errors else "PASS",
                "findings": [x.to_dict() for x in findings],
            },
        }
        if audit_errors and enforce_gates:
            errors += 1
        bench = family / "benchmark.json"
        if not bench.is_file():
            item["benchmark_audit"] = {
                "status": "FAIL",
                "errors": ["benchmark.json missing"],
            }
            errors += 1
            results.append(item)
            continue
        required_benchmark_dimensions = (
            set(map(str, profile.get("required_dimensions", [])))
            if profile.get("enforce_quality_gates", False)
            else set()
        )
        ba = audit_benchmark_manifest(
            bench, pattern, required_dimensions=required_benchmark_dimensions
        )
        item["benchmark_audit"] = ba
        if ba.get("status") != "PASS":
            errors += 1
        gates = profile.get("gates", {}) if profile else {}
        qa = quality_audit(
            bench,
            min_case_count=int(gates.get("min_total", 120) if profile else 120),
            min_positive=int(gates.get("min_positive", 40) if profile else 40),
            min_negative=int(gates.get("min_negative", 40) if profile else 40),
            min_unknown=int(gates.get("min_unknown", 20) if profile else 20),
            min_real_world=int(
                profile.get("min_real_world_cases", 0) if profile else 0
            ),
            required_dimensions=set(map(str, profile.get("required_dimensions", [])))
            if profile
            else set(),
            dimension_minima={
                str(k): int(v)
                for k, v in (profile.get("dimension_minima", {}) or {}).items()
            }
            if profile
            else {},
            min_dataset_sources=int(
                profile.get("min_dataset_sources", 0) if profile else 0
            ),
            min_repositories=int(profile.get("min_repositories", 0) if profile else 0),
            min_projects=int(profile.get("min_projects", 0) if profile else 0),
            min_cves=int(profile.get("min_cves", 0) if profile else 0),
            require_split_strategies=set(
                map(str, profile.get("required_split_strategies", []))
            )
            if profile
            else set(),
            require_label_provenance=bool(
                profile.get("require_label_provenance", False)
            )
            if profile
            else False,
            require_case_identity=bool(profile.get("require_case_identity", False))
            if profile
            else False,
            min_real_world_label_authority=int(
                (
                    profile.get(
                        "min_real_world_label_authority",
                        profile.get("require_real_world_label_authority", 0),
                    )
                    if profile
                    else 0
                )
                or 0
            ),
            require_negative_basis=bool(profile.get("require_negative_basis", False))
            if profile
            else False,
            require_source_similarity_audit=bool(
                profile.get("require_source_similarity_audit", False)
            )
            if profile
            else False,
            source_similarity_threshold=float(
                (profile.get("leakage_policy") or {}).get(
                    "normalized_source_similarity_threshold", 0.92
                )
            )
            if profile
            else 0.92,
        )
        item["quality_audit"] = qa
        if (
            enforce_gates
            and profile.get("enforce_quality_gates", False)
            and qa.get("status") != "PASS"
        ):
            errors += len(qa.get("errors", []))
        _, metrics, meta = run_manifest(
            bench,
            pattern,
            reveal=True,
            case_timeout_seconds=(
                (profile.get("performance") or {}).get("max_case_seconds")
                if profile
                else None
            ),
            required_dimensions=required_benchmark_dimensions,
            require_analyzer_attestation=bool(
                profile.get("require_analyzer_attestation", False)
            ),
        )
        md = metrics.to_dict()
        item["metrics"] = md
        item["coverage"] = meta
        # Attach the full quality-audit census so profile gates can distinguish independent samples from mutation descendants.
        meta["quality_audit"] = qa
        # Use pair/repository/project clusters as sampling units to avoid overconfident intervals.
        values = []
        unknown_values = []
        classification_rows = []
        case_by_id = {
            str(c.get("id")): c
            for c in json.loads(bench.read_text(encoding="utf-8")).get("cases", [])
            if isinstance(c, dict)
        }
        for rr in _:
            case = case_by_id.get(rr.case_id, {})
            ds = case.get("dataset") or {}
            cluster = str(
                case.get("pair_id")
                or ds.get("pair_id")
                or ds.get("repository")
                or ds.get("repo")
                or ds.get("project")
                or rr.case_id
            )
            values.append((cluster, 1.0 if rr.correct else 0.0))
            if rr.expected == "UNKNOWN":
                unknown_values.append(
                    (cluster, 1.0 if rr.actual in {"UNKNOWN", "PARTIAL"} else 0.0)
                )
            classification_rows.append(
                {
                    "case_id": rr.case_id,
                    "expected": rr.expected,
                    "actual": rr.actual,
                    "pair_id": case.get("pair_id") or ds.get("pair_id"),
                    "repository": ds.get("repository") or ds.get("repo"),
                    "project": ds.get("project"),
                    "dataset": ds.get("name"),
                }
            )
        meta["cluster_statistics"] = {
            "known_or_overall_correctness": cluster_bootstrap_mean(values)
            if values
            else {"mean": None, "ci95": [None, None], "clusters": 0},
            "unknown_safety": cluster_bootstrap_mean(unknown_values)
            if unknown_values
            else {"mean": None, "ci95": [None, None], "clusters": 0},
            "classification": cluster_bootstrap_binary_metrics(classification_rows)
            if classification_rows
            else {"status": "EMPTY", "clusters": 0, "ci95": {}},
            "unit": "pair/repository/project cluster",
        }
        if profile.get("require_stored_witness_replay", False):
            sr = _stored_replay_for_results(bench, pattern, _)
            item["stored_witness_replay"] = sr
            meta["stored_witness_replay"] = sr
            if enforce_gates and sr.get("status") != "PASS":
                errors += 1
        # Independent semantic replay across all MATCH results, not just one example.
        independent_validation = None
        if profile.get("require_independent_witness_validation", False):
            try:
                iv = validate_benchmark_matches(bench, pattern, only_status="MATCH")
                independent_validation = iv
                item["independent_witness_validation"] = iv
                meta["witness_validation"] = iv
                if enforce_gates and iv.get("status") != "PASS":
                    errors += 1
            except Exception as exc:
                independent_validation = {"status": "FAIL", "errors": [str(exc)]}
                item["independent_witness_validation"] = independent_validation
                meta["witness_validation"] = independent_validation
                if enforce_gates:
                    errors += 1
        else:
            gp = _family_graph_for_validation(bench)
            if gp:
                try:
                    g = parse_graph(gp)
                    m = (
                        __import__("evidencelab.matcher", fromlist=["Matcher"])
                        .Matcher(g)
                        .run(pattern)
                        .to_dict()
                    )
                    item["witness_validation"] = WitnessReplay(g, pattern).validate(m)
                    meta["witness_validation"] = item["witness_validation"]
                except Exception as exc:
                    item["witness_validation"] = {
                        "status": "FAIL",
                        "errors": [str(exc)],
                    }
                    meta["witness_validation"] = item["witness_validation"]
        q = compute_evidence_quality(_, pattern)
        if profile.get("require_performance_evaluation", False):
            perf = profile_pattern(
                bench,
                pattern,
                repeats=int((profile.get("performance") or {}).get("repeats", 1) or 1),
                max_case_seconds=(profile.get("performance") or {}).get(
                    "max_case_seconds"
                ),
                max_case_memory_bytes=(profile.get("performance") or {}).get(
                    "max_case_memory_bytes"
                ),
            )
            meta["performance"] = perf
            item["performance"] = perf
        if independent_validation is not None and q.get("matched_cases"):
            q["independent_replay_rate"] = float(
                independent_validation.get("passed_cases", 0)
            ) / float(q["matched_cases"])
        item["evidence_quality"] = q
        meta["evidence_quality"] = q
        for k in aggregate:
            if k in md and isinstance(md[k], (int, float)):
                aggregate[k] += md[k]
        if enforce_gates and profile:
            ge = validate_benchmark_gate(md, meta, profile, hidden=False)
            item["gate_errors"] = ge
            errors += len(ge)
        item["failure_taxonomy"] = taxonomy_payload(
            [str(x.message) for x in findings]
            + list(qa.get("errors", []))
            + list(item.get("gate_errors", []))
        )
        meta["failure_taxonomy"] = item["failure_taxonomy"]
        # Accept a family benchmark tree or a sealed bundle containing benchmark.json.
        if hidden_base:
            sealed_required = bool(
                require_hidden
                or profile.get("require_hidden_validation", False)
                or profile.get("require_hidden_hmac", False)
                or hidden_policy.get("require_external_origin", False)
            )
            if sealed_required and not (hidden_base / "seal.json").is_file():
                h_candidates = []
            else:
                h_candidates = [
                    hidden_base / family.name / "benchmark.json",
                    hidden_base / "benchmark.json",
                ]
            hidden = next((x for x in h_candidates if x.is_file()), None)
            if hidden:
                overlap = compare_manifests(bench, hidden)
                item["public_hidden_overlap"] = overlap
                if enforce_gates and overlap.get("status") != "PASS":
                    errors += 1
                hidden_results, hm, hmmeta = run_manifest(
                    hidden,
                    pattern,
                    reveal=True,
                    case_timeout_seconds=(
                        (profile.get("performance") or {}).get("max_case_seconds")
                        if profile
                        else None
                    ),
                    require_analyzer_attestation=bool(
                        profile.get("require_analyzer_attestation", False)
                    ),
                )
                item["hidden_metrics"] = hm.to_dict()
                item["hidden_coverage"] = hmmeta
                hidden_validation_result = None
                if profile.get("require_independent_witness_validation", False):
                    try:
                        hiv = validate_benchmark_matches(
                            hidden, pattern, only_status="MATCH"
                        )
                        hidden_validation_result = hiv
                        item["hidden_independent_witness_validation"] = hiv
                        hmmeta["witness_validation"] = hiv
                        if enforce_gates and hiv.get("status") != "PASS":
                            errors += 1
                    except Exception as exc:
                        hidden_validation_result = {
                            "status": "FAIL",
                            "errors": [str(exc)],
                        }
                        item["hidden_independent_witness_validation"] = (
                            hidden_validation_result
                        )
                        hmmeta["witness_validation"] = hidden_validation_result
                        if enforce_gates:
                            errors += 1
                if profile.get("require_performance_evaluation", False):
                    hperf = profile_pattern(
                        hidden,
                        pattern,
                        repeats=int(
                            (profile.get("performance") or {}).get("repeats", 1) or 1
                        ),
                        max_case_seconds=(profile.get("performance") or {}).get(
                            "max_case_seconds"
                        ),
                        max_case_memory_bytes=(profile.get("performance") or {}).get(
                            "max_case_memory_bytes"
                        ),
                    )
                    hmmeta["performance"] = hperf
                    item["hidden_performance"] = hperf
                qh = compute_evidence_quality(hidden_results, pattern)
                if hidden_validation_result is not None and qh.get("matched_cases"):
                    qh["independent_replay_rate"] = float(
                        hidden_validation_result.get("passed_cases", 0)
                    ) / float(qh["matched_cases"])
                hmmeta["evidence_quality"] = qh
                item["hidden_evidence_quality"] = qh
                hmmeta["hidden_integrity"] = hidden_integrity or {}
                if enforce_gates and profile:
                    ge = validate_benchmark_gate(
                        hm.to_dict(), hmmeta, profile, hidden=True
                    )
                    item["hidden_gate_errors"] = ge
                    errors += len(ge)
            elif require_hidden or profile.get("require_hidden_validation", False):
                item["hidden_metrics"] = None
                item["hidden_gate_errors"] = ["hidden benchmark missing for family"]
                errors += 1
        elif require_hidden or profile.get("require_hidden_validation", False):
            item["hidden_metrics"] = None
            item["hidden_gate_errors"] = ["hidden validation was not supplied"]
            errors += 1
        if enforce_gates and profile.get("require_split_artifacts", False):
            for strategy in map(str, profile.get("required_split_strategies", [])):
                split_dir = _find_split_dir(root, family, strategy)
                if split_dir is None:
                    item.setdefault("split_artifacts", {})[strategy] = {
                        "status": "FAIL",
                        "errors": ["split directory missing"],
                    }
                    errors += 1
                else:
                    sa = __import__(
                        "evidencelab.splits", fromlist=["audit_split_directory"]
                    ).audit_split_directory(split_dir, strategy=strategy)
                    item.setdefault("split_artifacts", {})[strategy] = sa
                    if sa.get("status") != "PASS":
                        errors += 1
        results.append(item)
    # A local placeholder cannot satisfy a requirement backed by an external --hidden-root.
    package = audit_research_package(
        root, require_hidden=False if hidden_base else require_hidden
    )
    if package["status"] == "FAIL":
        errors += len(package.get("errors", []))
    if hidden_integrity is not None:
        if hidden_integrity.get("status") != "PASS":
            errors += 1
    taxonomy_inputs = list(map(str, pre_gate_errors))
    for r in results:
        taxonomy_inputs.extend(
            str(x) for x in (r.get("quality_audit", {}) or {}).get("errors", [])
        )
        taxonomy_inputs.extend(str(x) for x in r.get("gate_errors", []))
        taxonomy_inputs.extend(str(x) for x in r.get("hidden_gate_errors", []))
        taxonomy_inputs.extend(
            str(x)
            for x in r.get("pattern_audit", {}).get("findings", [])
            if isinstance(x, dict)
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __import__("evidencelab").__version__,
        "root": str(root),
        "family_count": len(results),
        "status": "PASS" if errors == 0 else "FAIL",
        "errors": errors,
        "aggregate_metrics": aggregate,
        "hidden_integrity": hidden_integrity,
        "package_audit": package,
        "placeholder_audit": placeholder_audit,
        "pre_gate_errors": pre_gate_errors,
        "research_ledgers": ledger_audit,
        "failure_taxonomy": taxonomy_payload(taxonomy_inputs),
        "families": results,
    }
