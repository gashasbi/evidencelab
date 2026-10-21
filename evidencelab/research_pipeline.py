from __future__ import annotations
from . import SCHEMA_VERSION
from pathlib import Path
from typing import Any, Iterable
import json, shutil, os
from .benchmark_build import compose_benchmarks, benchmark_plan
from .benchmark_quality import quality_audit
from .corpus_runner import capture_dataset
from .profile import load_profile
from .contract import utc_now
from .provenance import sha256_file, sha256_json


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _cwe_tokens(value: Any) -> set[str]:
    """Normalize scalar, comma-separated, or nested CWE metadata."""
    if value is None or isinstance(value, dict):
        return set()

    if isinstance(value, (list, tuple, set)):
        result: set[str] = set()
        for item in value:
            result.update(_cwe_tokens(item))
        return result

    text = str(value).upper()
    return {
        part.strip()
        for part in text.replace(";", ",").split(",")
        if part.strip()
    }


def build_external_research_corpus(
    inputs: Iterable[str | Path],
    out_dir: str | Path,
    *,
    cwe: str | None = None,
    profile: str | Path | None = None,
    capture: bool = True,
    timeout: int = 600,
    limit: int | None = None,
    split: bool = True,
) -> dict[str, Any]:
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    in_paths = [Path(x).resolve() for x in inputs]
    if not in_paths:
        raise ValueError("at least one dataset manifest is required")
    staged = []
    capture_results = []
    for idx, src in enumerate(in_paths):
        raw = json.loads(src.read_text(encoding="utf-8"))
        if cwe:
            targets = _cwe_tokens(cwe)
            filtered = []
            for c in raw.get("cases", []):
                if not isinstance(c, dict):
                    continue

                ds = c.get("dataset") or {}
                dataset_cwe = ds.get("cwe") if isinstance(ds, dict) else None

                values = (
                    _cwe_tokens(c.get("source_cwe"))
                    | _cwe_tokens(c.get("cwe"))
                    | _cwe_tokens(dataset_cwe)
                )
                if targets.intersection(values):
                    filtered.append(c)
            if not filtered:
                raise ValueError(f"no cases matched requested CWE {cwe} in {src}")
            clone = dict(raw)
            clone["cases"] = filtered
            fp = out / "staged" / f"{idx:03d}-{src.stem}.json"
            fp.parent.mkdir(parents=True, exist_ok=True)
            # The staged manifest lives under out/staged, not beside the input
            # manifest. Resolve each source against its original manifest first;
            # otherwise relative source paths silently point at the wrong tree.
            for staged_case in clone["cases"]:
                if not isinstance(staged_case, dict):
                    continue
                source_ref = staged_case.get("source")
                if not isinstance(source_ref, str) or not source_ref:
                    continue
                source_path = Path(source_ref).expanduser()
                if not source_path.is_absolute():
                    source_path = src.parent / source_path
                staged_case["source"] = str(source_path.resolve())
            _write(fp, clone)
            src_for_capture = fp
        else:
            src_for_capture = src
        has_sources = any(
            isinstance(c, dict) and c.get("source")
            for c in json.loads(src_for_capture.read_text(encoding="utf-8")).get(
                "cases", []
            )
        )
        has_graphs = any(
            isinstance(c, dict) and c.get("graph")
            for c in json.loads(src_for_capture.read_text(encoding="utf-8")).get(
                "cases", []
            )
        )
        if capture and has_sources and has_graphs:
            raise ValueError(
                f"mixed source-only and graph-backed cases require an explicit pre-capture merge: {src_for_capture}"
            )
        if capture and has_sources:
            capdir = out / "captures" / f"{idx:03d}-{src.stem}"
            bench = out / f"captured-{idx:03d}-{src.stem}.json"
            r = capture_dataset(
                src_for_capture,
                capdir,
                bench,
                timeout=timeout,
                limit=limit,
                keep_failures_as_unknown=True,
            )
            capture_results.append(r)
            if r.get("status") == "FAIL":
                raise RuntimeError(
                    f"Joern capture failed for {src}: {r.get('failures')}"
                )
            captured_manifest = Path(r["benchmark"]).resolve()
            captured_raw = json.loads(
                captured_manifest.read_text(encoding="utf-8")
            )

            # capture_dataset writes graph and capture-manifest references
            # relative to the staged input manifest. The returned benchmark
            # lives at the corpus root, so normalize those paths before compose.
            staged_root = src_for_capture.parent.resolve()
            corpus_root = out.resolve()
            manifest_root = captured_manifest.parent.resolve()

            for captured_case in captured_raw.get("cases", []):
                if not isinstance(captured_case, dict):
                    continue

                case_id = str(captured_case.get("id", "<unknown>"))

                source_ref = captured_case.get("source")
                if isinstance(source_ref, str) and source_ref:
                    source_path = Path(source_ref).expanduser()
                    if not source_path.is_absolute():
                        source_path = staged_root / source_path
                    captured_case["source"] = os.path.relpath(
                        source_path.resolve(), manifest_root
                    )

                graph_ref = captured_case.get("graph")
                if isinstance(graph_ref, str) and graph_ref:
                    graph_path = Path(graph_ref).expanduser()
                    if not graph_path.is_absolute():
                        graph_path = staged_root / graph_path
                    graph_path = graph_path.resolve()

                    try:
                        graph_path.relative_to(corpus_root)
                    except ValueError as exc:
                        raise ValueError(
                            f"captured graph escapes research corpus root "
                            f"for case {case_id}: {graph_ref}"
                        ) from exc

                    if not graph_path.is_file():
                        raise FileNotFoundError(
                            f"captured graph missing for case {case_id}: "
                            f"{graph_path}"
                        )

                    captured_case["graph"] = os.path.relpath(
                        graph_path, manifest_root
                    )

                capture_info = captured_case.get("capture")
                if isinstance(capture_info, dict):
                    capture_ref = capture_info.get("manifest")
                    if isinstance(capture_ref, str) and capture_ref:
                        capture_path = Path(capture_ref).expanduser()
                        if not capture_path.is_absolute():
                            capture_path = staged_root / capture_path
                        capture_path = capture_path.resolve()

                        try:
                            capture_path.relative_to(corpus_root)
                        except ValueError as exc:
                            raise ValueError(
                                f"capture manifest escapes research corpus root "
                                f"for case {case_id}: {capture_ref}"
                            ) from exc

                        if not capture_path.is_file():
                            raise FileNotFoundError(
                                f"capture manifest missing for case {case_id}: "
                                f"{capture_path}"
                            )

                        capture_info["manifest"] = os.path.relpath(
                            capture_path, manifest_root
                        )

            _write(captured_manifest, captured_raw)
            staged.append(captured_manifest)
        else:
            staged.append(src_for_capture)
    composed = out / "benchmark.json"
    comp = compose_benchmarks(staged, composed, copy_graphs=True, include_unknown=True)
    result = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-research-corpus-build",
        "created_at_utc": utc_now(),
        "inputs": [str(x) for x in in_paths],
        "benchmark": str(composed),
        "composition": comp,
        "capture_results": capture_results,
    }
    if profile:
        prof = load_profile(profile)
        result["readiness"] = benchmark_plan(composed, prof)
        result["quality"] = quality_audit(
            composed,
            min_case_count=int((prof.get("gates") or {}).get("min_total", 0)),
            min_positive=int((prof.get("gates") or {}).get("min_positive", 0)),
            min_negative=int((prof.get("gates") or {}).get("min_negative", 0)),
            min_unknown=int((prof.get("gates") or {}).get("min_unknown", 0)),
            min_real_world=int(prof.get("min_real_world_cases", 0) or 0),
            required_dimensions=set(map(str, prof.get("required_dimensions", []))),
            dimension_minima={
                str(k): int(v) for k, v in (prof.get("dimension_minima") or {}).items()
            },
            min_dataset_sources=int(prof.get("min_dataset_sources", 0) or 0),
            min_repositories=int(prof.get("min_repositories", 0) or 0),
            min_projects=int(prof.get("min_projects", 0) or 0),
            min_cves=int(prof.get("min_cves", 0) or 0),
            require_split_strategies=set(
                map(str, prof.get("required_split_strategies", []))
            ),
            require_label_provenance=bool(prof.get("require_label_provenance")),
            require_case_identity=bool(prof.get("require_case_identity")),
            min_real_world_label_authority=int(
                prof.get("min_real_world_label_authority", 0) or 0
            ),
            require_negative_basis=bool(prof.get("require_negative_basis", False)),
        )
    if split:
        from .splits import split_benchmark, chronological_split, audit_split_directory

        split_dir = out / "splits"
        try:
            sr = split_benchmark(
                composed, split_dir, "repository", allow_missing_group=False
            )
        except Exception as exc:
            sr = {"status": "FAIL", "errors": [str(exc)]}
        result["repository_split"] = sr
        result["repository_split_audit"] = (
            audit_split_directory(split_dir, strategy="repository")
            if sr.get("status") == "PASS"
            else None
        )
        try:
            cr = chronological_split(
                composed, split_dir / "chronological", allow_missing_date=False
            )
            result["chronological_split"] = cr
            result["chronological_split_audit"] = (
                audit_split_directory(split_dir / "chronological")
                if cr.get("status") == "PASS"
                else None
            )
        except Exception as exc:
            result["chronological_split"] = {"status": "FAIL", "errors": [str(exc)]}
        actual_strategies = []
        if result.get("repository_split", {}).get("status") == "PASS":
            actual_strategies.append("repository")
        if result.get("chronological_split", {}).get("status") == "PASS":
            actual_strategies.append("chronological")
        if actual_strategies:
            composed_raw = json.loads(composed.read_text(encoding="utf-8"))
            split_meta = dict(composed_raw.get("split") or {})
            split_meta["strategies"] = sorted(
                set(map(str, split_meta.get("strategies", []))) | set(actual_strategies)
            )
            split_meta["artifacts_root"] = str(split_dir.resolve())
            composed_raw["schema_version"] = SCHEMA_VERSION
            composed_raw["split"] = split_meta
            composed.write_text(
                json.dumps(composed_raw, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    split_failures = [
        x
        for x in (result.get("repository_split"), result.get("chronological_split"))
        if isinstance(x, dict) and x.get("status") == "FAIL"
    ]
    capture_failures = [x for x in capture_results if x.get("status") == "FAIL"]
    result["status"] = (
        "PASS"
        if comp.get("status") in {"PASS", "WARN"}
        and not split_failures
        and not capture_failures
        else "FAIL"
    )
    result["errors"] = []
    for failure in split_failures:
        result["errors"].extend(failure.get("errors", []))
    for failure in capture_failures:
        result["errors"].extend(failure.get("errors", failure.get("failures", [])))
    result["build_sha256"] = sha256_json(result)
    _write(out / "build-report.json", result)
    return result


def research_readiness(
    root: str | Path, profile: str | Path, *, hidden_root: str | Path | None = None
) -> dict[str, Any]:
    from .research_check import run_research_check

    r = run_research_check(
        root, profile, hidden_root=hidden_root, enforce_gates=True, require_hidden=True
    )
    blocks = []
    for fam in r.get("families", []):
        q = fam.get("quality_audit") or {}
        blocks.extend(
            {"family": fam["family"], "kind": "quality", "message": x}
            for x in q.get("errors", [])
        )
        blocks.extend(
            {"family": fam["family"], "kind": "gate", "message": x}
            for x in fam.get("gate_errors", [])
        )
        blocks.extend(
            {"family": fam["family"], "kind": "hidden", "message": x}
            for x in fam.get("hidden_gate_errors", [])
        )
    blocks.extend(
        {"family": "__project__", "kind": "project", "message": x}
        for x in r.get("pre_gate_errors", [])
    )
    unique = []
    index = {}
    for b in blocks:
        key = (b["kind"], b["message"])
        if key not in index:
            index[key] = len(unique)
            unique.append({"kind": b["kind"], "message": b["message"], "families": []})
        item = unique[index[key]]
        if b["family"] not in item["families"]:
            item["families"].append(b["family"])
    by_category = {}
    for b in unique:
        by_category[b["kind"]] = by_category.get(b["kind"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": r.get("tool_version"),
        "status": r.get("status"),
        "family_count": r.get("family_count", 0),
        "blocking_conditions": blocks,
        "unique_blockers": unique,
        "blocker_counts_by_kind": by_category,
        "blocking_condition_count": len(blocks),
        "unique_blocker_count": len(unique),
        "hidden_integrity": r.get("hidden_integrity"),
        "recommended_next_actions": sorted(set(_recommend(blocks))),
        "source_check": r,
    }


def _recommend(blocks: list[dict[str, Any]]) -> list[str]:
    out = []
    text = " ".join(str(x.get("message", "")).lower() for x in blocks)
    if "independent" in text or "corpus" in text:
        out.append(
            "Add independently sourced cases; mutation descendants must not be used to meet corpus-size gates."
        )
    if (
        "real-world" in text
        or "repository diversity" in text
        or "cve diversity" in text
    ):
        out.append(
            "Add real-world cases with repository, revision, vulnerability/patch and provenance metadata."
        )
    if "hidden" in text:
        out.append(
            "Have an external evaluator provide a separate hidden benchmark sealed with HMAC; do not derive it from the public package for publication claims."
        )
    if "control_conditions" in text:
        out.append(
            "Add explicit guard/control-condition cases including dominated, non-dominated and wrong-object guards."
        )
    if "analysis_completeness" in text:
        out.append(
            "Add analysis-completeness cases where missing/truncated analysis must yield UNKNOWN."
        )
    if "split" in text:
        out.append(
            "Create repository/project and chronological splits and audit them for pair, graph and source leakage."
        )
    if not out:
        out.append(
            "Review the full research report and independent witness validation before claiming publication readiness."
        )
    return out
