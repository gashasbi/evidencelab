from __future__ import annotations

"""Researcher-defined experimental material mapping for EvidenceLab.

This layer is intentionally narrower than a dataset platform. It answers only:
which parts of an external source are the cases/artifacts/claims/locations/relation
material needed to run an Evidence experiment? The researcher declares the mapping.
"""

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from . import SCHEMA_VERSION
from .provenance import sha256_file, sha256_json

ALLOWED_INPUT_TYPES = {"records", "directory"}
ALLOWED_FORMATS = {"json", "jsonl", "ndjson", "csv"}
TRUTH = {
    "bad": "BAD",
    "flawed": "BAD",
    "vulnerable": "BAD",
    "positive": "BAD",
    "1": "BAD",
    "true": "BAD",
    "good": "GOOD",
    "safe": "GOOD",
    "fixed": "GOOD",
    "negative": "GOOD",
    "0": "GOOD",
    "false": "GOOD",
    "mixed": "MIXED",
    "unknown": "UNKNOWN",
    "partial": "UNKNOWN",
    "": "UNKNOWN",
}


def _load_model(path: str | Path) -> dict[str, Any]:
    p = Path(path).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("dataset model root must be an object")
    return raw


def _get(obj: Any, path: str) -> Any:
    if path in {"", "."}:
        return obj
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _transform(value: Any, transform: str | None) -> Any:
    t = str(transform or "identity").lower()
    if t == "identity":
        return value
    if t == "string":
        return None if value is None else str(value)
    if t == "int":
        if value is None or value == "":
            return None
        return int(value)
    if t == "float":
        if value is None or value == "":
            return None
        return float(value)
    if t == "list":
        if value is None:
            return []
        return value if isinstance(value, list) else [value]
    if t == "cwe":
        import re

        if value is None:
            return None
        m = re.search(r"(?i)cwe[-_ ]?(\d+)", str(value))
        return (
            f"CWE-{m.group(1)}"
            if m
            else (f"CWE-{value}" if str(value).isdigit() else str(value))
        )
    if t == "truth":
        raw = "" if value is None else str(value).strip().lower()
        return TRUTH.get(raw, "UNKNOWN")
    if t == "basename":
        return Path(str(value)).name if value is not None else None
    raise ValueError(f"unsupported transform: {transform}")


def _mapped(spec: Any, record: dict[str, Any]) -> Any:
    if not isinstance(spec, dict) or "path" not in spec:
        raise ValueError("mapping entries must contain path")
    return _transform(_get(record, str(spec["path"])), spec.get("transform"))


def _read_records(path: Path, fmt: str) -> list[dict[str, Any]]:
    if fmt == "json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if isinstance(raw, dict):
            for k in ("cases", "test_cases", "data", "records", "items"):
                if isinstance(raw.get(k), list):
                    return [x for x in raw[k] if isinstance(x, dict)]
            return [raw]
        raise ValueError("JSON input must be an object or array")
    if fmt in {"jsonl", "ndjson"}:
        out = []
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            if line.strip():
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("JSONL records must be objects")
                out.append(obj)
        return out
    if fmt == "csv":
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            return [dict(r) for r in csv.DictReader(f)]
    raise ValueError(f"unsupported record format: {fmt}")


def _safe_under(root: Path, raw_path: str) -> Path:
    p = Path(raw_path)
    if p.is_absolute():
        raise PermissionError(f"absolute artifact path is forbidden: {raw_path}")
    target = (root / p).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise PermissionError(f"artifact path escapes source_root: {raw_path}") from exc
    return target


def validate_model(path: str | Path) -> dict[str, Any]:
    p = Path(path).resolve()
    try:
        m = _load_model(p)
        errors: list[str] = []
        if str(m.get("schema_version")) != SCHEMA_VERSION:
            errors.append("schema_version must be the current contract version")
        ds = m.get("dataset")
        if (
            not isinstance(ds, dict)
            or not ds.get("id")
            or not ds.get("name")
            or not ds.get("version")
        ):
            errors.append("dataset.id, dataset.name and dataset.version are required")
        inp = m.get("input") or {}
        if inp.get("type", "records") not in ALLOWED_INPUT_TYPES:
            errors.append("input.type must be records or directory")
        if (
            inp.get("type", "records") == "records"
            and str(inp.get("format", "")).lower() not in ALLOWED_FORMATS
        ):
            errors.append("records input requires format json/jsonl/ndjson/csv")
        case = m.get("case") or {}
        if not isinstance(case.get("id"), dict):
            errors.append("case.id mapping is required")
        if "truth" in case and not isinstance(case["truth"], dict):
            errors.append("case.truth must be an object")
        for key in ("claims", "artifacts", "locations", "relations"):
            if key in case and not isinstance(case[key], list):
                errors.append(f"case.{key} must be an array")
        if errors:
            return {"status": "FAIL", "source": str(p), "errors": errors}
        return {
            "status": "PASS",
            "source": str(p),
            "errors": [],
            "schema_version": SCHEMA_VERSION,
            "mapping_digest": sha256_json(m),
        }
    except Exception as exc:
        return {"status": "FAIL", "source": str(p), "errors": [str(exc)]}


def _record_from_directory(root: Path) -> list[dict[str, Any]]:
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            out.append(
                {"__evidencelab_path__": rel, "__evidencelab_sha256__": sha256_file(p)}
            )
    return out


def materialize(path: str | Path) -> dict[str, Any]:
    model_path = Path(path).resolve()
    model = _load_model(model_path)
    root = (model_path.parent / str(model.get("source_root", "."))).resolve()
    if not root.exists():
        raise FileNotFoundError(f"source_root does not exist: {root}")
    inp = model.get("input") or {"type": "records"}
    if inp.get("type", "records") == "directory":
        records = _record_from_directory(_safe_under(root, str(inp.get("path", "."))))
    else:
        input_path = _safe_under(root, str(inp.get("path", "")))
        if not input_path.is_file():
            raise FileNotFoundError(f"record input does not exist: {input_path}")
        records = _read_records(
            input_path, str(inp.get("format", input_path.suffix.lstrip("."))).lower()
        )

    case_spec = model.get("case") or {}
    cases = []
    for idx, record in enumerate(records):
        cid = _mapped(case_spec["id"], record)
        if cid in (None, ""):
            cid = f"case-{idx:08d}"
        cid = str(cid)
        truth_raw = None
        truth_state = "UNKNOWN"
        authority = "DATASET_DECLARED"
        if isinstance(case_spec.get("truth"), dict):
            ts = case_spec["truth"].get("state")
            if isinstance(ts, dict):
                truth_raw = _mapped(ts, record)
                truth_state = _transform(truth_raw, "truth")
            else:
                truth_raw = ts
                truth_state = _transform(truth_raw, "truth")
            authority = str(case_spec["truth"].get("authority", "DATASET_DECLARED"))
        claims = []
        for spec in case_spec.get("claims", []) or []:
            value = (
                _mapped(spec["value"], record)
                if isinstance(spec.get("value"), dict)
                else spec.get("value")
            )
            claims.append(
                {
                    "type": str(spec.get("type", "claim")),
                    "value": value,
                    "authority": str(spec.get("authority", authority)),
                }
            )
        artifacts = []
        for spec in case_spec.get("artifacts", []) or []:
            aid = str(spec.get("id", "artifact"))
            kind = str(spec.get("kind", "artifact"))
            path_value = _mapped(spec["path"], record)
            if path_value is None:
                artifacts.append(
                    {"id": aid, "kind": kind, "status": "UNRESOLVED", "path": None}
                )
                continue
            target = _safe_under(root, str(path_value))
            if not target.is_file():
                artifacts.append(
                    {
                        "id": aid,
                        "kind": kind,
                        "status": "MISSING",
                        "path": str(path_value),
                    }
                )
            else:
                artifacts.append(
                    {
                        "id": aid,
                        "kind": kind,
                        "status": "READY",
                        "path": str(target.relative_to(root).as_posix()),
                        "sha256": sha256_file(target),
                        "size": target.stat().st_size,
                    }
                )
        locations = []
        for spec in case_spec.get("locations", []) or []:
            loc = {"artifact": str(spec.get("artifact", ""))}
            for dest in (
                "line",
                "column",
                "start_line",
                "end_line",
                "start_column",
                "end_column",
                "offset",
                "length",
            ):
                if dest in spec:
                    val = spec[dest]
                    loc[dest] = _mapped(val, record) if isinstance(val, dict) else val
            locations.append(loc)
        relations = []
        for spec in case_spec.get("relations", []) or []:
            rel = {}
            for k, v in spec.items():
                rel[k] = (
                    _mapped(v, record) if isinstance(v, dict) and "path" in v else v
                )
            relations.append(rel)
        cases.append(
            {
                "id": cid,
                "truth": {
                    "state": truth_state,
                    "raw": truth_raw,
                    "authority": authority,
                },
                "claims": claims,
                "artifacts": artifacts,
                "locations": locations,
                "relations": relations,
                "source_record": record,
                "source_record_index": idx,
            }
        )
    dataset = dict(model.get("dataset") or {})
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-canonical-experimental-material",
        "dataset": dataset,
        "mapping_source": str(model_path),
        "mapping_sha256": sha256_file(model_path),
        "source_root": str(root),
        "case_count": len(cases),
        "cases": cases,
    }
    return payload


def write_materialized(model_path: str | Path, out: str | Path) -> dict[str, Any]:
    result = materialize(model_path)
    dst = Path(out).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    states = {
        s: sum(c["truth"]["state"] == s for c in result["cases"])
        for s in ["BAD", "GOOD", "MIXED", "UNKNOWN"]
    }
    return {
        "status": "PASS",
        "out": str(dst),
        "schema_version": SCHEMA_VERSION,
        "case_count": result["case_count"],
        "truth_counts": states,
        "mapping_sha256": result["mapping_sha256"],
    }
