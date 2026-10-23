#!/usr/bin/env python3
"""Create a self-contained evaluation tree for every existing family of one CWE.

The benchmark and graph semantics are not changed. The helper copies the same
captured cases/graphs and (when present) source files into each family directory,
so EvidenceLab's existing research-check command can evaluate each current pattern
against one identical corpus without changing the repository's reference datasets.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any


def safe_name(value: Any, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._-")
    return text[:100] or fallback


def resolve_reference(base: Path, value: str) -> Path:
    ref = Path(value).expanduser()
    return (ref if ref.is_absolute() else base / ref).resolve()


def _require_within(path: Path, roots: list[Path], *, description: str) -> None:
    for root in roots:
        try:
            path.relative_to(root)
            return
        except ValueError:
            continue
    raise ValueError(f"{description} resolves outside the allowed roots: {path}")


def materialize(
    benchmark_path: Path,
    pattern_root: Path,
    out_root: Path,
    *,
    allowed_source_roots: list[Path] | None = None,
) -> dict[str, Any]:
    benchmark_path = benchmark_path.resolve()
    corpus_root = benchmark_path.parent
    pattern_root = pattern_root.resolve()
    out_root = out_root.resolve()
    source_roots = [corpus_root] + [
        Path(x).expanduser().resolve() for x in (allowed_source_roots or [])
    ]
    raw = json.loads(benchmark_path.read_text(encoding="utf-8"))
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("the captured benchmark must contain a non-empty cases array")
    patterns = sorted(pattern_root.glob("*/pattern.json"))
    if not patterns:
        raise ValueError(f"no existing patterns found under {pattern_root}")

    family_summaries = []
    for pattern_path in patterns:
        family_name = pattern_path.parent.name
        family_dir = out_root / "families" / family_name
        graphs_dir = family_dir / "graphs"
        sources_dir = family_dir / "source"
        graphs_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pattern_path, family_dir / "pattern.json")
        copied_cases = []
        missing_graphs = []
        missing_sources = []

        for index, original in enumerate(cases):
            if not isinstance(original, dict):
                raise ValueError(f"benchmark case at index {index} is not an object")
            case = dict(original)
            case_id = str(case.get("id") or f"case-{index:06d}")
            slug = safe_name(case_id, f"case-{index:06d}")
            graph_ref = case.get("graph")
            if not isinstance(graph_ref, str) or not graph_ref:
                raise ValueError(f"{case_id}: graph reference is missing")
            graph_source = resolve_reference(corpus_root, graph_ref)
            _require_within(
                graph_source, [corpus_root], description=f"{case_id} graph reference"
            )
            if not graph_source.is_file():
                missing_graphs.append({"id": case_id, "graph": str(graph_ref)})
                continue
            graph_name = f"{index:06d}-{slug}{graph_source.suffix or '.json'}"
            graph_target = graphs_dir / graph_name
            shutil.copy2(graph_source, graph_target)
            case["graph"] = f"graphs/{graph_name}"

            source_ref = case.get("source")
            if isinstance(source_ref, str) and source_ref:
                source_source = resolve_reference(corpus_root, source_ref)
                _require_within(
                    source_source,
                    source_roots,
                    description=f"{case_id} source reference",
                )
                if source_source.is_file():
                    sources_dir.mkdir(parents=True, exist_ok=True)
                    source_name = f"{index:06d}-{slug}{source_source.suffix or '.c'}"
                    source_target = sources_dir / source_name
                    shutil.copy2(source_source, source_target)
                    case["source"] = f"source/{source_name}"
                else:
                    missing_sources.append({"id": case_id, "source": str(source_ref)})
                    case["source_missing_original"] = str(source_ref)
                    case["source_missing_reason"] = (
                        "source was not resolvable when materializing evaluation tree"
                    )
                    case.pop("source", None)
            copied_cases.append(case)

        if missing_graphs:
            raise ValueError(
                f"{family_name}: {len(missing_graphs)} graph assets are missing; first={missing_graphs[:3]}"
            )
        family_benchmark = dict(raw)
        family_benchmark["cases"] = copied_cases
        family_benchmark["manifest_id"] = (
            f"{raw.get('manifest_id', benchmark_path.stem)}-{family_name}"
        )
        family_metadata = family_benchmark.get("metadata")
        if not isinstance(family_metadata, dict):
            family_metadata = {}
        family_metadata["materialized_for_pattern"] = family_name
        family_metadata["materialization_policy"] = (
            "copy unchanged graph/source content; rewrite only local paths"
        )
        family_benchmark["metadata"] = family_metadata
        (family_dir / "benchmark.json").write_text(
            json.dumps(family_benchmark, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        family_summaries.append(
            {
                "family": family_name,
                "cases": len(copied_cases),
                "graphs_copied": len(copied_cases),
                "source_files_missing": len(missing_sources),
                "missing_sources": missing_sources[:50],
                "path": str(family_dir),
            }
        )

    return {
        "status": "PASS",
        "cwe_pattern_root": str(pattern_root),
        "source_benchmark": str(benchmark_path),
        "case_count": len(cases),
        "family_count": len(family_summaries),
        "families": family_summaries,
        "out_root": str(out_root),
        "note": "Materialization preserves the original labels and evidence artifacts; it does not make them independently validated ground truth.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument(
        "--pattern-root",
        type=Path,
        required=True,
        help="folder containing family-name/pattern.json directories",
    )
    parser.add_argument(
        "--out-root",
        type=Path,
        required=True,
        help="evaluation project root; a families/ directory is created here",
    )
    parser.add_argument(
        "--allowed-source-root",
        type=Path,
        action="append",
        default=[],
        help="additional trusted roots from which declared source files may be copied; may be repeated",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = materialize(
            args.benchmark,
            args.pattern_root,
            args.out_root,
            allowed_source_roots=args.allowed_source_root,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}, indent=2
            ),
            file=sys.stderr,
        )
        return 2
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
