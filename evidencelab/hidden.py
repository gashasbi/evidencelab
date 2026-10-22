from __future__ import annotations
import hashlib, hmac, json, os, shutil
from pathlib import Path
from typing import Any
from .parsers import parse_graph
from .provenance import sha256_file, sha256_json
from . import SCHEMA_VERSION

SUPPORTED_HIDDEN_SCHEMA_VERSIONS = {SCHEMA_VERSION}

_SENSITIVE_HIDDEN_KEYS = {
    "source",
    "sourcemetadata",
    "sourcetext",
    "sourcecode",
    "rawsource",
    "rawrecord",
    "rawrecords",
    "record",
    "records",
    "sourcefile",
    "sourceroot",
    "localpath",
    "filepath",
    "absolutepath",
    "checkoutpath",
    "root",
    "sourcepath",
    "localdirectory",
    "workspacepath",
    "repositorypath",
}


def _redact_hidden_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redact_hidden_value(item)
            for key, item in value.items()
            if "".join(ch for ch in str(key).lower() if ch.isalnum())
            not in _SENSITIVE_HIDDEN_KEYS
        }
    if isinstance(value, list):
        return [_redact_hidden_value(item) for item in value]
    return value


def _hidden_sensitive_paths(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            normalized = "".join(ch for ch in str(key).lower() if ch.isalnum())
            if normalized in _SENSITIVE_HIDDEN_KEYS:
                found.append(child)
            else:
                found.extend(_hidden_sensitive_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_hidden_sensitive_paths(item, f"{path}[{index}]"))
    return found


def _safe(base: Path, rel: str) -> Path:
    p = (base / rel).resolve()
    try:
        p.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"path escapes bundle root: {rel}") from exc
    return p


def _key_bytes(key: str | bytes | None) -> bytes | None:
    if key is None:
        return None
    return key if isinstance(key, bytes) else key.encode("utf-8")


def seal_hidden_benchmark(
    source: str | Path,
    out_dir: str | Path,
    key: str | bytes | None = None,
    *,
    require_hmac: bool = False,
    origin: str = "external-evaluator",
) -> dict[str, Any]:
    src = Path(source).resolve()
    dst = Path(out_dir).resolve()
    if dst == src or src in dst.parents:
        raise ValueError(
            "hidden bundle must not be created inside the source benchmark"
        )
    if require_hmac and not key:
        raise ValueError("require_hmac=True requires a non-empty HMAC key")
    if origin not in {"external-evaluator", "source-derived-demo"}:
        raise ValueError("invalid hidden origin")
    dst.mkdir(parents=True, exist_ok=True)
    graph_dir = dst / "graphs"
    graph_dir.mkdir(exist_ok=True)
    raw = json.loads(src.read_text(encoding="utf-8"))
    cases = []
    ids = set()
    if str(raw.get("schema_version")) not in SUPPORTED_HIDDEN_SCHEMA_VERSIONS:
        raise ValueError("unsupported hidden source benchmark schema_version")
    for case in raw.get("cases", []):
        if not isinstance(case, dict) or not case.get("graph"):
            raise ValueError("hidden benchmark cases must contain graph paths")
        cid = str(case.get("id", ""))
        if not cid or cid in ids:
            raise ValueError("hidden benchmark case ids must be unique and non-empty")
        ids.add(cid)
        gp = _safe(src.parent, str(case["graph"]))
        if not gp.is_file():
            raise ValueError(f"hidden graph missing: {gp}")
        digest = parse_graph(gp).digest()
        name = hashlib.sha256((cid + "|" + digest).encode()).hexdigest()[:28] + ".json"
        out_graph = graph_dir / name
        shutil.copy2(gp, out_graph)
        clone = _redact_hidden_value(json.loads(json.dumps(case)))
        clone["partition"] = "hidden"
        clone["graph"] = str(out_graph.relative_to(dst))
        clone["graph_sha256"] = sha256_file(out_graph)

        clone.pop("source_metadata", None)
        clone.pop("source", None)
        ds = clone.get("dataset")
        if isinstance(ds, dict):
            for k in ("source_file", "root", "source_root", "local_path"):
                ds.pop(k, None)
        cases.append(clone)
    if not cases:
        raise ValueError("hidden benchmark must contain at least one case")
    manifest = _redact_hidden_value(dict(raw))
    manifest.update(
        {
            "schema_version": SCHEMA_VERSION,
            "format": "evidencelab-hidden-benchmark",
            "partition": "hidden",
            "manifest_id": str(raw.get("manifest_id", src.stem)) + "-sealed",
            "cases": cases,
            "hidden_policy": {
                "origin": origin,
                "confidentiality": "filesystem-access-controlled",
                "case_metadata_redacted": True,
                "researcher_access": "forbidden",
                "hmac_required": bool(require_hmac),
            },
        }
    )
    mp = dst / "benchmark.json"
    mp.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    digest = sha256_file(mp)
    graph_files = sorted(graph_dir.glob("*.json"))
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-hidden-seal",
        "benchmark_sha256": digest,
        "case_count": len(cases),
        "graph_count": len(graph_files),
        "origin": origin,
        "hmac_required": bool(require_hmac),
        "bundle_sha256": sha256_json(
            {
                "benchmark_sha256": digest,
                "graphs": sorted(sha256_file(p) for p in graph_files),
            }
        ),
    }
    kb = _key_bytes(key)
    if kb:
        envelope["hmac_sha256"] = hmac.new(
            kb, json.dumps(envelope, sort_keys=True).encode(), hashlib.sha256
        ).hexdigest()
    (dst / "seal.json").write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    try:
        os.chmod(dst, 0o700)
        os.chmod(mp, 0o600)
        os.chmod(dst / "seal.json", 0o600)
    except OSError:
        pass
    return {
        "status": "PASS",
        "bundle": str(dst),
        "benchmark": str(mp),
        "seal": str(dst / "seal.json"),
        "case_count": len(cases),
        "hmac_present": bool(kb),
        "origin": origin,
    }


def verify_hidden_bundle(
    bundle: str | Path,
    key: str | bytes | None = None,
    *,
    require_hmac: bool = False,
    require_external_origin: bool = False,
) -> dict[str, Any]:
    root = Path(bundle).resolve()
    mp = root / "benchmark.json"
    sp = root / "seal.json"
    errors = []
    if not mp.is_file() or not sp.is_file():
        return {
            "status": "FAIL",
            "errors": ["benchmark.json or seal.json missing"],
            "hmac_present": False,
        }
    try:
        seal = json.loads(sp.read_text(encoding="utf-8"))
        manifest = json.loads(mp.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "status": "FAIL",
            "errors": [f"invalid hidden JSON: {exc}"],
            "hmac_present": False,
        }
    if not isinstance(seal, dict) or not isinstance(manifest, dict):
        return {
            "status": "FAIL",
            "errors": ["hidden seal and benchmark manifest must be JSON objects"],
            "hmac_present": False,
        }
    raw_cases = manifest.get("cases", [])
    if not isinstance(raw_cases, list):
        errors.append("hidden benchmark cases must be a list")
        raw_cases = []
    if str(manifest.get("schema_version")) not in SUPPORTED_HIDDEN_SCHEMA_VERSIONS:
        errors.append("unsupported hidden benchmark schema_version")
    if manifest.get("partition") != "hidden":
        errors.append("hidden benchmark partition must be hidden")
    if seal.get("format") != "evidencelab-hidden-seal":
        errors.append("invalid hidden seal format")
    try:
        declared_case_count = int(seal.get("case_count", -1))
    except (TypeError, ValueError):
        declared_case_count = -1
        errors.append("hidden seal case_count is invalid")
    if declared_case_count != len(raw_cases):
        errors.append("hidden seal case_count mismatch")
    if require_external_origin and seal.get("origin") != "external-evaluator":
        errors.append("hidden bundle origin is not external-evaluator")
    effective_hmac_required = bool(require_hmac or seal.get("hmac_required"))
    if effective_hmac_required and not seal.get("hmac_sha256"):
        errors.append(
            "HMAC seal required by caller or seal policy but bundle has no hmac_sha256"
        )
    actual = sha256_file(mp)
    if actual != seal.get("benchmark_sha256"):
        errors.append("benchmark sha256 mismatch")
    graphs = root / "graphs"
    graph_digests = []
    ids = set()
    referenced_graphs = set()
    seen_graph_digests: dict[str, str] = {}
    for case in raw_cases:
        if not isinstance(case, dict):
            errors.append("hidden benchmark case entry must be an object")
            continue
        cid = str(case.get("id", ""))
        if not cid or cid in ids:
            errors.append(f"duplicate/empty hidden case id: {cid or '<empty>'}")
        ids.add(cid)
        if case.get("partition") != "hidden":
            errors.append(f"hidden case not marked hidden: {cid}")
        leaked_fields = _hidden_sensitive_paths(case)
        if leaked_fields:
            errors.append(
                f"hidden source metadata leakage: {cid}: {', '.join(leaked_fields[:10])}"
            )
        graph_ref = str(case.get("graph", ""))
        try:
            gp = _safe(root, graph_ref)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"invalid hidden graph path for {cid}: {exc}")
            continue
        referenced_graphs.add(gp.resolve())
        if not gp.is_file():
            errors.append(f"missing hidden graph: {graph_ref}")
            continue
        actual_graph_digest = sha256_file(gp)
        if case.get("graph_sha256") and actual_graph_digest != case["graph_sha256"]:
            errors.append(f"hidden graph sha256 mismatch: {cid}")
        previous = seen_graph_digests.get(actual_graph_digest)
        if previous and previous != cid:
            errors.append(f"duplicate hidden graph content: {cid} and {previous}")
        else:
            seen_graph_digests[actual_graph_digest] = cid
        graph_digests.append(actual_graph_digest)
    actual_graph_files = (
        {x.resolve() for x in graphs.glob("*.json")} if graphs.is_dir() else set()
    )
    try:
        declared_graph_count = int(seal.get("graph_count", -1))
    except (TypeError, ValueError):
        declared_graph_count = -1
        errors.append("hidden seal graph_count is invalid")
    if declared_graph_count != len(actual_graph_files):
        errors.append("hidden seal graph_count mismatch")
    if actual_graph_files != referenced_graphs:
        extras = sorted(
            str(x.relative_to(root)) for x in actual_graph_files - referenced_graphs
        )
        outside = sorted(
            str(x.relative_to(root)) for x in referenced_graphs - actual_graph_files
        )
        if extras:
            errors.append(
                "unreferenced hidden graph artifacts present: " + ", ".join(extras[:20])
            )
        if outside:
            errors.append(
                "referenced hidden graphs are outside graphs directory: "
                + ", ".join(outside[:20])
            )
    expected_bundle = seal.get("bundle_sha256")
    actual_bundle = sha256_json(
        {"benchmark_sha256": actual, "graphs": sorted(graph_digests)}
    )
    if expected_bundle and expected_bundle != actual_bundle:
        errors.append("hidden bundle sha256 mismatch")
    manifest_leaks = _hidden_sensitive_paths(manifest)
    if manifest_leaks:
        errors.append(
            "hidden manifest contains sensitive metadata fields: "
            + ", ".join(manifest_leaks[:10])
        )
    kb = _key_bytes(key)
    hmac_present = bool(seal.get("hmac_sha256"))
    if hmac_present:
        if not kb:
            errors.append("bundle is HMAC-sealed but no verification key was supplied")
        else:
            unsigned = dict(seal)
            unsigned.pop("hmac_sha256", None)
            actual_mac = hmac.new(
                kb, json.dumps(unsigned, sort_keys=True).encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(str(seal["hmac_sha256"]), actual_mac):
                errors.append("seal HMAC mismatch")
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "case_count": len(raw_cases),
        "bundle_sha256": actual_bundle,
        "hmac_present": hmac_present,
        "origin": seal.get("origin"),
        "hmac_required": effective_hmac_required,
    }
