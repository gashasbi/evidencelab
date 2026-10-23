from __future__ import annotations

"""EvidenceLab artifact and research-contract helpers.

The contract layer is deliberately separate from the matcher.  It answers questions such
as "is this artifact reproducible and correctly identified?" without deciding whether a
vulnerability exists.
"""

from pathlib import Path
from typing import Any, Iterable
import datetime as _dt
import hashlib
import json
import os
import re
import tarfile
import tempfile

from . import SCHEMA_VERSION, __version__, SUPPORTED_SCHEMA_VERSIONS
from .provenance import sha256_file, sha256_json, environment_snapshot

ARTIFACT_FORMATS = {
    "evidencelab-canonical-graph",
    "evidencelab-benchmark",
    "evidencelab-evaluation-case",
    "evidencelab-evaluation",
    "evidencelab-research-package",
    "evidencelab-submission",
    "evidencelab-witness-report",
}


def utc_now() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )


def _safe_rel(root: Path, candidate: str) -> Path:
    p = (root / candidate).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes root: {candidate}") from exc
    return p


def artifact_identity(
    path: str | Path, *, kind: str | None = None, root: str | Path | None = None
) -> dict[str, Any]:
    p = Path(path).resolve()
    if not p.is_file():
        raise ValueError(f"artifact not found: {p}")
    rel = None
    if root is not None:
        try:
            rel = str(p.relative_to(Path(root).resolve()))
        except ValueError:
            rel = str(p)
    return {
        "path": rel or str(p),
        "sha256": sha256_file(p),
        "size": p.stat().st_size,
        "kind": kind,
    }


def artifact_envelope(
    *,
    kind: str,
    content: Any,
    producer: str = "EvidenceLab",
    producer_version: str = __version__,
    provenance: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if kind not in ARTIFACT_FORMATS:
        raise ValueError(f"unsupported artifact kind: {kind}")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "artifact": {
            "kind": kind,
            "artifact_id": f"art-{sha256_json(content)[:20]}",
            "created_at_utc": utc_now(),
            "producer": {"name": producer, "version": producer_version},
        },
        "provenance": list(provenance or []),
        "content": content,
    }
    payload["artifact"]["content_sha256"] = sha256_json(content)
    payload["artifact"]["envelope_sha256"] = sha256_json(
        {k: v for k, v in payload.items() if k != "artifact"}
        | {
            "artifact": {
                k: v for k, v in payload["artifact"].items() if k != "envelope_sha256"
            }
        }
    )
    return payload


def validate_artifact_envelope(
    raw: dict[str, Any], *, expected_kind: str | None = None
) -> list[str]:
    errors: list[str] = []
    if not isinstance(raw, dict):
        return ["artifact envelope must be an object"]
    if str(raw.get("schema_version")) not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(
            f"unsupported schema_version {raw.get('schema_version')}; supported={sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )
    art = raw.get("artifact")
    if not isinstance(art, dict):
        errors.append("artifact metadata is required")
        return errors
    kind = str(art.get("kind", ""))
    if kind not in ARTIFACT_FORMATS:
        errors.append(f"unsupported artifact kind: {kind}")
    if expected_kind and kind != expected_kind:
        errors.append(f"artifact kind mismatch: {kind} != {expected_kind}")
    for field in ("artifact_id", "created_at_utc", "producer", "content_sha256"):
        if not art.get(field):
            errors.append(f"artifact.{field} is required")
    if "content" not in raw:
        errors.append("artifact content is required")
    else:
        expected = art.get("content_sha256")
        actual = sha256_json(raw["content"])
        if expected and expected != actual:
            errors.append("artifact.content_sha256 mismatch")
    return errors


def research_tree_inventory(
    root: str | Path,
    *,
    include_hidden: bool = False,
    include_external_data: bool = False,
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    files = []
    excluded_parts = {".git", ".venv", "__pycache__", ".pytest_cache", "dist", "build"}
    if not include_hidden:
        excluded_parts |= {"hidden", "evaluator-only"}
    if not include_external_data:
        excluded_parts |= {"datasets/raw", "corpus/raw"}
    for p in sorted(rootp.rglob("*")):
        if not p.is_file():
            continue
        if p.is_symlink():
            target = p.resolve()
            try:
                target.relative_to(rootp)
            except ValueError:
                raise ValueError(f"research package contains symlink outside root: {p}")
        rel = p.relative_to(rootp)
        rel_text = rel.as_posix()
        if any(part in excluded_parts for part in rel.parts) or (
            not include_external_data
            and (
                rel_text.startswith("datasets/raw/")
                or rel_text.startswith("corpus/raw/")
            )
        ):
            continue
        files.append(artifact_identity(p, root=rootp))
    return {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-research-package",
        "package_id": f"research-{sha256_json([x['sha256'] for x in files])[:20]}",
        "root": str(rootp),
        "created_at_utc": utc_now(),
        "evidencelab_version": __version__,
        "environment": environment_snapshot(rootp),
        "include_hidden": include_hidden,
        "include_external_data": include_external_data,
        "artifacts": files,
    }


def write_research_inventory(
    root: str | Path,
    out: str | Path,
    *,
    include_hidden: bool = False,
    include_external_data: bool = False,
) -> dict[str, Any]:
    payload = research_tree_inventory(
        root, include_hidden=include_hidden, include_external_data=include_external_data
    )
    payload["inventory_sha256"] = sha256_json(payload)
    op = Path(out)
    op.parent.mkdir(parents=True, exist_ok=True)
    op.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def verify_research_inventory(manifest: str | Path) -> dict[str, Any]:
    mp = Path(manifest).resolve()
    raw = json.loads(mp.read_text(encoding="utf-8"))
    root_raw = raw.get("root")
    if root_raw is None or str(root_raw).strip() == "":
        root = mp.parent.resolve()
    else:
        root_value = Path(str(root_raw))
        root = (
            root_value.resolve()
            if root_value.is_absolute()
            else (mp.parent / root_value).resolve()
        )
    errors: list[str] = []
    checked = 0
    for item in raw.get("artifacts", []):
        rel = str(item.get("path", ""))
        try:
            p = _safe_rel(root, rel)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not p.is_file():
            errors.append(f"missing artifact: {rel}")
            continue
        checked += 1
        if sha256_file(p) != str(item.get("sha256")):
            errors.append(f"sha256 mismatch: {rel}")
    expected = raw.get("inventory_sha256")
    body = dict(raw)
    body.pop("inventory_sha256", None)
    if expected and expected != sha256_json(body):
        errors.append("inventory_sha256 mismatch")
    return {
        "status": "PASS" if not errors else "FAIL",
        "checked": checked,
        "errors": errors,
    }


def audit_no_placeholders(
    root: str | Path, *, allow_scaffold: bool = True
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    hits: list[dict[str, Any]] = []
    candidates = list(rootp.glob("families/*/pattern.json")) + list(
        rootp.glob("evidence/families/*/pattern.json")
    )
    if (rootp / "evidence/pattern.json").is_file():
        candidates.append(rootp / "evidence/pattern.json")
    marker_re = re.compile(
        r"\bTODO\b|PLACEHOLDER|RESEARCH_TEMPLATE|TEMPLATE_ONLY", re.I
    )
    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        for idx, line in enumerate(text.splitlines(), 1):
            if marker_re.search(line):
                hits.append(
                    {
                        "path": str(p.relative_to(rootp)),
                        "line": idx,
                        "text": line.strip()[:240],
                    }
                )
    scaffold = (
        allow_scaffold
        and not list(rootp.glob("families/*/pattern.json"))
        and not list(rootp.glob("evidence/families/*/pattern.json"))
    )
    return {
        "status": "SCAFFOLD" if scaffold else ("FAIL" if hits else "PASS"),
        "placeholders": hits,
        "scaffold": scaffold,
    }


def build_coverage_matrix(cases: list[dict[str, Any]]) -> dict[str, Any]:
    aliases = {
        "guard_dominance": "control_conditions",
        "incomplete_analysis": "analysis_completeness",
        "mutate_extent_only": "mutation",
        "mutate_object_only": "mutation",
        "mutate_analysis_completeness": "mutation",
        "real_corpus": "real_world",
    }
    dims: set[str] = set()
    labels = ["MATCH", "NO_MATCH", "UNKNOWN"]
    matrix: dict[str, dict[str, int]] = {}
    for c in cases:
        exp = str(c.get("expected", "UNKNOWN")).upper()
        values = set(map(str, c.get("dimensions", []))) | set(
            map(str, c.get("tags", []))
        )
        canonical = {aliases.get(v, v) for v in values}
        dims |= canonical
        for d in canonical:
            matrix.setdefault(d, {x: 0 for x in labels})
            if exp in matrix[d]:
                matrix[d][exp] += 1
    return {
        "dimensions": sorted(dims),
        "labels": labels,
        "matrix": {k: matrix[k] for k in sorted(matrix)},
    }


def bundle_research_package(
    root: str | Path,
    out: str | Path,
    *,
    include_public_data: bool = True,
    include_hidden: bool = False,
    include_external_data: bool = False,
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    outp = Path(out).resolve()
    outp.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidencelab-bundle-") as td:
        stage = Path(td) / rootp.name
        stage.mkdir(parents=True, exist_ok=True)
        inventory = research_tree_inventory(
            rootp,
            include_hidden=include_hidden,
            include_external_data=include_external_data,
        )
        for item in inventory["artifacts"]:
            src = _safe_rel(rootp, str(item["path"]))
            rel = Path(str(item["path"]))

            dst = stage / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())

        staged_inventory = research_tree_inventory(
            stage,
            include_hidden=include_hidden,
            include_external_data=include_external_data,
        )

        staged_inventory["root"] = ".."
        inv = stage / "provenance" / "research-inventory.json"
        inv.parent.mkdir(parents=True, exist_ok=True)
        inv.write_text(
            json.dumps(staged_inventory, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        with tarfile.open(outp, "w:gz", compresslevel=6) as tar:
            tar.add(stage, arcname=stage.name, recursive=True)
    return {
        "status": "PASS",
        "bundle": str(outp),
        "sha256": sha256_file(outp),
        "bytes": outp.stat().st_size,
        "include_hidden": include_hidden,
        "include_public_data": include_public_data,
        "include_external_data": include_external_data,
    }
