from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, json, re
from . import SCHEMA_VERSION

REQUIRED_DIRS = (
    "evidence",
    "benchmarks",
    "experiments",
    "notes",
    "queries",
    "corpus",
    "provenance",
)
REQUIRED_FILES = ("task.json", "research-plan.md", "README.md")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def discover_families(root: str | Path) -> list[Path]:
    root = Path(root).resolve()
    found = list(root.glob("families/*/pattern.json")) + list(
        root.glob("evidence/families/*/pattern.json")
    )
    return sorted({p.parent for p in found})


def source_fingerprint(path: Path) -> str:
    """Stable text fingerprint used only for corpus leakage detection, not proof."""
    text = path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"//.*|/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\b(?:[A-Za-z_]\w*)\b", "ID", text)
    return hashlib.sha256(text.encode()).hexdigest()


def audit_research_package(
    root: str | Path, require_hidden: bool = False
) -> dict[str, Any]:
    root = Path(root).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    for d in REQUIRED_DIRS:
        if not (root / d).is_dir():
            warnings.append(f"recommended directory missing: {d}")
    for f in REQUIRED_FILES:
        if not (root / f).is_file():
            warnings.append(f"recommended research file missing: {f}")
    task = {}
    tp = root / "task.json"
    if tp.is_file():
        try:
            task = json.loads(tp.read_text(encoding="utf-8"))
            cwe = str(task.get("cwe", "")).upper()
            if not re.fullmatch(r"CWE-\d+", cwe):
                errors.append("task.cwe must look like CWE-123")
            rq = (
                task.get("research_question")
                or task.get("title")
                or task.get("scope", {}).get("principle")
            )
            if not rq:
                errors.append("task.research_question (or title/principle) is required")
            scope = task.get("in_scope", task.get("scope", {}).get("in_scope", []))
            if not isinstance(scope, (list, str)):
                errors.append("task must declare in_scope dimensions")
        except Exception as exc:
            errors.append(f"invalid task.json: {exc}")
    fams = discover_families(root)
    scaffold_only = (
        not fams
        and (root / "family-template.json").is_file()
        and (root / "evidence/pattern.json").is_file()
    )
    if not fams and not scaffold_only:
        errors.append("no Evidence Families found")
    family_reports = []
    from .spec import Pattern
    from .audit import audit_pattern
    from .evaluator import audit_benchmark_manifest

    for family in fams:
        pattern_path = family / "pattern.json"
        bench = family / "benchmark.json"
        try:
            pattern = Pattern.load(pattern_path)
        except Exception as exc:
            errors.append(f"{family.name}: invalid pattern: {exc}")
            continue
        findings = audit_pattern(
            pattern,
            {
                "min_required_claims": 6,
                "min_concepts": 3,
                "min_required_claim_kinds": 3,
                "min_provenance": 2,
                "require_counter_evidence": True,
                "require_coverage": True,
                "require_query_provenance": True,
            },
        )
        family_report = {
            "family": family.name,
            "pattern": str(pattern_path.relative_to(root)),
            "pattern_audit": [x.to_dict() for x in findings],
        }
        if not bench.is_file():
            errors.append(f"{family.name}: benchmark.json missing")
        else:
            # Package audit is structural; publication dimension requirements belong to the
            # caller/profile evaluation and must not leak into development/package discovery.
            ba = audit_benchmark_manifest(
                bench, pattern, strict=False, required_dimensions=set()
            )
            family_report["benchmark_audit"] = ba
            if ba.get("status") != "PASS":
                errors.append(f"{family.name}: benchmark audit failed")
        if any(x.severity == "ERROR" for x in findings):
            errors.append(f"{family.name}: pattern audit failed")
        family_report["provenance_count"] = len(pattern.provenance)
        family_reports.append(family_report)
    hidden_marker = root / "benchmarks/hidden/benchmark.json"
    hidden_count = 0
    if hidden_marker.is_file():
        try:
            hidden_raw = json.loads(hidden_marker.read_text(encoding="utf-8"))
            hidden_count = (
                len(hidden_raw.get("cases", [])) if isinstance(hidden_raw, dict) else 0
            )
        except Exception:
            hidden_count = 0
    if require_hidden and hidden_count == 0:
        errors.append(
            "publication-grade research requires an evaluator-controlled non-empty hidden benchmark"
        )
    exp = root / "experiments" / "experiment-ledger.jsonl"
    if exp.is_file():
        try:
            from .experiment import audit_experiment_ledger

            ea = audit_experiment_ledger(root)
            if ea["status"] != "PASS":
                errors.extend([f"experiment ledger: {x}" for x in ea["errors"]])
        except Exception as exc:
            errors.append(f"experiment ledger audit failed: {exc}")
    else:
        warnings.append(
            "experiment ledger missing: no reproducible experiment chain found"
        )
    try:
        from .research_records import audit_research_ledgers

        la = audit_research_ledgers(root)
    except Exception as exc:
        la = {"status": "FAIL", "errors": [str(exc)], "ledgers": {}}
    if la.get("status") == "FAIL":
        errors.extend([f"research ledger: {x}" for x in la.get("errors", [])])
    status = "FAIL" if errors else ("SCAFFOLD" if scaffold_only else "PASS")
    if scaffold_only:
        warnings.append(
            "research scaffold created; at least one executable Evidence Family must be added before validation"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "family_count": len(family_reports),
        "families": family_reports,
        "task": task,
        "research_ledgers": la,
    }
