from __future__ import annotations
from . import SCHEMA_VERSION

from pathlib import Path
from typing import Any, Iterable
import csv
import hashlib
import json
import re
import shutil

C_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}


def _norm_cwe(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    match = re.search(r"(?i)CWE[-_ ]?(\d+)", text)
    if match:
        return f"CWE-{match.group(1)}"
    if text.isdigit():
        return f"CWE-{text}"
    return None


def _infer_cwe(text: str) -> str | None:
    return _norm_cwe(text)


def _source_hashes(text: str) -> tuple[str, str]:
    raw = text.encode("utf-8", errors="replace")
    normalized = (
        "\n".join(
            line.rstrip() for line in text.replace("\r\n", "\n").split("\n")
        ).strip()
        + "\n"
    )
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(
        normalized.encode("utf-8", errors="replace")
    ).hexdigest()


def _label_provenance(
    authority: str,
    source: str,
    record_id: str | None = None,
    rationale: str | None = None,
) -> dict[str, Any]:
    out = {"authority": authority, "source": source}
    if record_id is not None:
        out["record_id"] = str(record_id)
    if rationale:
        out["rationale"] = rationale
    return out


def _target_label(value: Any) -> str:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"1", "true", "vulnerable", "bad", "flaw"}:
        return "MATCH"
    if text in {"0", "false", "benign", "safe", "good", "fixed"}:
        return "NO_MATCH"
    return "UNKNOWN"


def _read_rows(path: Path) -> list[dict[str, Any]]:
    # Parquet is binary: dispatch before any text decoding to avoid reading the
    # entire file into a temporary Unicode string and potentially failing decode.
    if path.suffix.lower() == ".parquet":
        try:
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise RuntimeError(
                "Parquet input requires the optional pyarrow dependency: pip install evidencelab[realdata]"
            ) from exc
        table = pq.read_table(path)
        return [dict(x) for x in table.to_pylist()]

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".json":
        raw = json.loads(text)
        rows = (
            raw
            if isinstance(raw, list)
            else raw.get("cases", raw.get("test_cases", raw.get("data", [])))
        )
    elif path.suffix.lower() in {".jsonl", ".ndjson"}:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        rows = list(csv.DictReader(text.splitlines()))
    return [r for r in rows if isinstance(r, dict)]

def _write_manifest(
    out_manifest: str | Path, dataset: dict[str, Any], cases: list[dict[str, Any]]
) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-dataset-manifest",
        "dataset": dataset,
        "case_count": len(cases),
        "cases": cases,
    }
    out = Path(out_manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {"status": "PASS", "case_count": len(cases), "manifest": str(out)}


def import_juliet(
    source_root: str | Path,
    out_manifest: str | Path,
    cwe: str | None = None,
    partition: str = "public",
    copy_source: bool = False,
    copy_root: str | Path | None = None,
    label_mode: str = "unknown",
) -> dict[str, Any]:
    """Import the public Juliet source corpus without inventing labels.

    Juliet files can contain paired bad/good code and multi-file test cases. A whole-file
    MATCH/NO_MATCH assignment based only on a filename is therefore not a sound default.
    `label_mode=unknown` preserves this fact. `label_mode=heuristic` is available for
    exploratory work and records the heuristic in every case.
    """
    if label_mode not in {"unknown", "heuristic"}:
        raise ValueError("label_mode must be 'unknown' or 'heuristic'")
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError(f"Juliet source root does not exist: {root}")
    target = Path(copy_root).resolve() if copy_root else None
    if target:
        target.mkdir(parents=True, exist_ok=True)
    requested_cwe = _norm_cwe(cwe)
    cases: list[dict[str, Any]] = []
    heuristic_count = 0

    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in C_EXTS:
            continue
        rel = p.relative_to(root)
        inferred = _infer_cwe(rel.as_posix())
        if requested_cwe and inferred and inferred != requested_cwe:
            continue
        if requested_cwe and not inferred:
            continue
        record_path = rel.as_posix()
        if copy_source and target:
            dst = (
                target
                / f"{hashlib.sha256(str(rel).encode()).hexdigest()[:16]}-{p.name}"
            )
            shutil.copy2(p, dst)
            record_path = str(dst.relative_to(target))

        label = "UNKNOWN"
        label_source = (
            "not assigned: Juliet test files may contain paired bad/good code"
        )
        if label_mode == "heuristic":
            name = p.name.lower()
            if re.search(r"(^|_)(bad)(_|\.)", name):
                label = "MATCH"
            elif re.search(r"(^|_)(good)(_|\.)", name):
                label = "NO_MATCH"
            else:
                parent_text = "/".join(x.lower() for x in p.parts)
                if "good" in parent_text and "bad" not in parent_text:
                    label = "NO_MATCH"
                elif "bad" in parent_text and "good" not in parent_text:
                    label = "MATCH"
            label_source = "filename/path heuristic"
            heuristic_count += int(label != "UNKNOWN")

        case_id = f"juliet-{hashlib.sha256(str(rel).encode()).hexdigest()[:20]}"
        tags = ["real_corpus", "juliet"]
        dimensions = ["real_corpus"]
        if label == "UNKNOWN":
            tags.append("label_unknown")
        else:
            dimensions.append("labelled")
        raw_sha, normalized_sha = _source_hashes(
            p.read_text(encoding="utf-8", errors="replace")
        )
        rec = {
            "id": case_id,
            "expected": label,
            "case_identity": {
                "record_id": case_id,
                "source_sha256": raw_sha,
                "normalized_source_hash": normalized_sha,
            },
            "source_sha256": raw_sha,
            "normalized_source_hash": normalized_sha,
            "source": record_path,
            "source_cwe": inferred or requested_cwe,
            "partition": partition,
            "tags": tags,
            "dimensions": dimensions,
            "dataset": {
                "name": "Juliet C/C++ 1.3",
                "dataset_version": "1.3",
                "relative_path": rel.as_posix(),
                "label_source": label_source,
                "label_mode": label_mode,
                "license": "CC0 1.0 / public-domain notice as published by NIST",
            },
        }
        if label in {"MATCH", "NO_MATCH"}:
            rec["label_provenance"] = _label_provenance(
                "HEURISTIC" if label_mode == "heuristic" else "EXPLICIT",
                "filename/path heuristic"
                if label_mode == "heuristic"
                else "Juliet explicit label metadata",
                case_id,
            )
        cases.append(rec)
    result = _write_manifest(
        out_manifest,
        {
            "name": "Juliet C/C++ 1.3",
            "version": "1.3",
            "current_sard_suite": "116 (Juliet C/C++ 1.3.1 with extra support)",
            "current_sard_suite_url": "https://samate.nist.gov/SARD/test-suites/116",
            "root": str(root),
            "label_policy": "unknown-by-default; heuristic only when explicitly requested",
            "source_url": "https://samate.nist.gov/SARD/test-suites/112",
            "acquisition_url": "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip",
        },
        cases,
    )
    result["heuristic_label_count"] = heuristic_count
    result["label_mode"] = label_mode
    return result


def import_sard_table(
    source_file: str | Path,
    out_manifest: str | Path,
    cwe: str | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    p = Path(source_file).resolve()
    rows = _read_rows(p)
    requested_cwe = _norm_cwe(cwe)
    root = Path(source_root).resolve() if source_root else p.parent
    cases: list[dict[str, Any]] = []
    for i, row in enumerate(rows):
        cw = _norm_cwe(
            row.get("cwe") or row.get("CWE") or row.get("weakness")
        ) or _infer_cwe(str(row))
        if requested_cwe and cw and cw != requested_cwe:
            continue
        src = (
            row.get("source")
            or row.get("path")
            or row.get("file")
            or row.get("filename")
        )
        raw_label = (
            row.get("state") if row.get("state") is not None else row.get("label")
        )
        if raw_label is None:
            raw_label = (
                row.get("status")
                if row.get("status") is not None
                else row.get("good_bad")
            )
        label = _target_label(raw_label)
        rec: dict[str, Any] = {
            "id": str(row.get("id") or row.get("test_id") or f"sard-{i:07d}"),
            "expected": label,
            "source": str(src) if src else None,
            "source_cwe": cw or requested_cwe,
            "partition": str(row.get("partition") or "public"),
            "tags": ["real_corpus", "sard"],
            "dimensions": ["real_corpus"],
            "dataset": {
                "name": "NIST SARD import",
                "label_source": "source metadata field",
                "original_id": row.get("id") or row.get("test_id"),
            },
        }
        if src:
            sp = (root / str(src)).resolve()
            try:
                sp.relative_to(root)
                if sp.is_file():
                    rec["source_sha256"] = hashlib.sha256(sp.read_bytes()).hexdigest()
            except ValueError:
                rec["dataset"]["source_path_warning"] = (
                    "source escaped declared source_root"
                )
        # Preserve original fields instead of dropping useful SARD metadata.
        rec["dataset"]["original_fields"] = row
        cases.append(rec)
    return _write_manifest(
        out_manifest,
        {
            "name": "NIST SARD import",
            "source_file": str(p),
            "source_url": "https://samate.nist.gov/SARD",
        },
        cases,
    )


def _primevul_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def import_primevul_jsonl(
    source_file: str | Path,
    out_manifest: str | Path,
    output_source_root: str | Path,
    cwe: str | None = None,
) -> dict[str, Any]:
    src = Path(source_file).resolve()
    outsrc = Path(output_source_root).resolve()
    outsrc.mkdir(parents=True, exist_ok=True)
    requested_cwe = _norm_cwe(cwe)
    cases: list[dict[str, Any]] = []
    with src.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if not line.strip():
                continue
            row = json.loads(line)
            cw = _norm_cwe(_primevul_value(row, "cwe", "CWE", "cwe_id", "CWE ID"))
            cwe_raw = _primevul_value(row, "cwe", "CWE", "cwe_id", "CWE ID")
            if isinstance(cwe_raw, list):
                cw_list = [_norm_cwe(x) for x in cwe_raw]
            else:
                cw_list = [cw] if cw else []
            if requested_cwe and requested_cwe not in cw_list:
                continue
            func = _primevul_value(row, "func", "function", "code", "source")
            if not isinstance(func, str) or not func.strip():
                continue
            project = (
                _primevul_value(row, "project", "repo", "repository")
                or "unknown-project"
            )
            commit = (
                _primevul_value(row, "commit_id", "commit", "hash", "revision")
                or "unknown-commit"
            )
            target = _primevul_value(row, "target", "label", "vulnerable")
            expected = _target_label(target)
            stem = hashlib.sha256(f"{project}|{commit}|{idx}".encode()).hexdigest()[:20]
            extension = (
                ".c"
                if str(_primevul_value(row, "language", "lang") or "").lower() == "c"
                else ".cpp"
            )
            file = outsrc / f"{stem}{extension}"
            # Do not append bytes to the imported function: source hashes describe
            # the exact dataset code string and must match the saved artifact.
            file.write_bytes(func.encode("utf-8"))
            cve = _primevul_value(row, "CVE ID", "cve", "CVE", "cve_id")
            commit_url = _primevul_value(row, "commit_url", "commitURL", "commit_link")
            repo_url = _primevul_value(row, "project_url", "repo_url", "repository_url")
            original_file = _primevul_value(
                row, "file", "file_path", "filepath", "path", "filename"
            )
            date = _primevul_value(row, "commit_date", "date", "published", "timestamp")
            tags = ["real_corpus", "primevul", "real_world"] + (
                ["positive"]
                if expected == "MATCH"
                else ["negative"]
                if expected == "NO_MATCH"
                else ["unknown"]
            )
            dimensions = [
                "real_corpus",
                "real_world",
                "provenance",
                "repository",
                "project",
            ]
            if cve:
                dimensions.append("cve")
            if commit_url:
                dimensions.append("commit_identity")
            raw_sha, normalized_sha = _source_hashes(func)
            cases.append(
                {
                    "id": f"primevul-{stem}",
                    "expected": expected,
                    "label_provenance": _label_provenance(
                        "DATASET",
                        "PrimeVul target/label field",
                        str(_primevul_value(row, "id", "sample_id", "idx") or stem),
                    ),
                    "case_identity": {
                        "record_id": str(
                            _primevul_value(row, "id", "sample_id", "idx") or stem
                        ),
                        "repository": str(project),
                        "commit": str(commit),
                        "source_sha256": raw_sha,
                        "normalized_source_hash": normalized_sha,
                    },
                    "source_content_sha256": raw_sha,
                    "normalized_source_hash": normalized_sha,
                    "source": str(file.relative_to(outsrc.parent)),
                    "partition": str(row.get("partition") or "public"),
                    "tags": tags,
                    "dimensions": dimensions,
                    "dataset": {
                        "name": "PrimeVul",
                        "project": project,
                        "repository": project,
                        "commit": commit,
                        "commit_id": commit,
                        "commit_url": commit_url,
                        "repository_url": repo_url,
                        "cve": cve,
                        "cwe": cw_list or cwe_raw,
                        "file": original_file,
                        "date": date,
                        "label_source": "PrimeVul target/label field",
                        "source_url": "https://github.com/DLVulDet/PrimeVul",
                        "provenance_url": commit_url
                        or repo_url
                        or "https://github.com/DLVulDet/PrimeVul",
                        "source_record_index": idx,
                    },
                    "source_metadata": row,
                }
            )
    return _write_manifest(
        out_manifest,
        {
            "name": "PrimeVul import",
            "source_file": str(src),
            "source_url": "https://github.com/DLVulDet/PrimeVul",
        },
        cases,
    )


def import_secvuleval_jsonl(
    source_file: str | Path,
    out_manifest: str | Path,
    output_source_root: str | Path,
    cwe: str | None = None,
) -> dict[str, Any]:
    """Import SecVulEval-style JSON/JSONL while preserving CVE/patch/context metadata.

    SecVulEval releases have evolved; this importer intentionally accepts common aliases
    for code, target, CVE, repository, commit and fix/context fields and stores the full
    original row under `source_metadata` so no benchmark-specific information is lost.
    """
    src = Path(source_file).resolve()
    outsrc = Path(output_source_root).resolve()
    outsrc.mkdir(parents=True, exist_ok=True)
    rows = _read_rows(src)
    requested_cwe = _norm_cwe(cwe)
    cases: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        raw_cwe = _primevul_value(
            row, "cwe", "CWE", "cwe_id", "CWE ID", "cwe_list", "weakness"
        )
        cws = (
            [_norm_cwe(x) for x in raw_cwe]
            if isinstance(raw_cwe, list)
            else [_norm_cwe(raw_cwe)]
        )
        cws = [x for x in cws if x]
        if requested_cwe and requested_cwe not in cws:
            continue
        code = _primevul_value(
            row,
            "func",
            "function",
            "code",
            "source",
            "function_code",
            "func_body",
            "vulnerable_function",
            "non_vulnerable_function",
        )
        if not isinstance(code, str) or not code.strip():
            continue
        target = _primevul_value(
            row, "target", "label", "vulnerable", "is_vulnerable", "y"
        )
        expected = _target_label(target)
        project = (
            _primevul_value(row, "project", "repo", "repository", "project_name")
            or "unknown-project"
        )
        commit = (
            _primevul_value(
                row, "commit", "commit_id", "revision", "hash", "commit_hash"
            )
            or "unknown-commit"
        )
        cve = _primevul_value(row, "cve", "CVE", "CVE ID", "cve_id", "cve_list")
        file_path = _primevul_value(
            row, "file", "file_path", "filepath", "path", "filename"
        )
        fix = _primevul_value(
            row, "fix", "patch", "patch_diff", "diff", "commit_message"
        )
        date = _primevul_value(row, "date", "commit_date", "published", "timestamp")
        stem = hashlib.sha256(
            f"secvuleval|{project}|{commit}|{cve}|{idx}".encode()
        ).hexdigest()[:20]
        language = str(_primevul_value(row, "language", "lang") or "").lower()
        extension = ".c" if language == "c" else ".cpp"
        file = outsrc / f"{stem}{extension}"
        # Do not append bytes to the imported function: source hashes describe
        # the exact dataset code string and must match the saved artifact.
        file.write_bytes(code.encode("utf-8"))
        tags = ["real_corpus", "secvuleval", "real_world"] + (
            ["positive"]
            if expected == "MATCH"
            else ["negative"]
            if expected == "NO_MATCH"
            else ["unknown"]
        )
        dimensions = [
            "real_corpus",
            "real_world",
            "provenance",
            "repository",
            "project",
        ]
        if cve:
            dimensions.append("cve")
        if fix is not None:
            dimensions.append("patch_context")
        raw_sha, normalized_sha = _source_hashes(code)
        cases.append(
            {
                "id": f"secvuleval-{stem}",
                "expected": expected,
                "label_provenance": _label_provenance(
                    "DATASET",
                    "SecVulEval target/label field",
                    str(_primevul_value(row, "id", "sample_id", "idx") or stem),
                ),
                "case_identity": {
                    "record_id": str(
                        _primevul_value(row, "id", "sample_id", "idx") or stem
                    ),
                    "repository": str(project),
                    "commit": str(commit),
                    "source_sha256": raw_sha,
                    "normalized_source_hash": normalized_sha,
                },
                "source_content_sha256": raw_sha,
                "normalized_source_hash": normalized_sha,
                "source": str(file.relative_to(outsrc.parent)),
                "partition": str(row.get("partition") or "public"),
                "tags": tags,
                "dimensions": dimensions,
                "dataset": {
                    "name": "SecVulEval",
                    "project": project,
                    "repository": project,
                    "commit": commit,
                    "cve": cve,
                    "cwe": cws,
                    "file": file_path,
                    "date": date,
                    "patch_context": fix,
                    "label_source": "SecVulEval target/label field",
                    "source_url": "https://github.com/basimbd/SecVulEval",
                    "provenance_url": "https://github.com/basimbd/SecVulEval",
                    "source_record_index": idx,
                },
                "source_metadata": row,
            }
        )
    return _write_manifest(
        out_manifest,
        {
            "name": "SecVulEval import",
            "source_file": str(src),
            "source_url": "https://github.com/basimbd/SecVulEval",
        },
        cases,
    )


def merge_dataset_manifests(
    inputs: Iterable[str | Path], out_manifest: str | Path
) -> dict[str, Any]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    datasets: list[dict[str, Any]] = []
    for path in inputs:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        datasets.append(raw.get("dataset", {}))
        for c in raw.get("cases", []):
            cid = str(c.get("id"))
            if cid in seen:
                cid = f"{Path(path).stem}:{cid}"
            seen.add(cid)
            item = dict(c)
            item["id"] = cid
            merged.append(item)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-dataset-manifest",
        "datasets": datasets,
        "case_count": len(merged),
        "cases": merged,
    }
    out = Path(out_manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {"status": "PASS", "case_count": len(merged), "manifest": str(out)}


def _archive_member_source(root: Path, candidate: str) -> Path | None:
    p = (root / candidate).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        return None
    return p if p.is_file() else None


def index_dataset_archive(
    archive: str | Path, out_manifest: str | Path
) -> dict[str, Any]:
    """Index a NIST/SARD/other ZIP without assigning vulnerability labels.

    This is intentionally an *indexer*, not a label generator. It records archive names,
    file counts, likely source files and SHA256s only for reproducibility.
    """
    import zipfile

    ap = Path(archive).resolve()
    if not ap.is_file():
        raise ValueError(f"archive not found: {ap}")
    entries = []
    with zipfile.ZipFile(ap) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            suffix = Path(name).suffix.lower()
            kind = (
                "source"
                if suffix in C_EXTS
                else (
                    "metadata"
                    if suffix
                    in {
                        ".json",
                        ".jsonl",
                        ".csv",
                        ".xml",
                        ".yaml",
                        ".yml",
                        ".txt",
                        ".md",
                    }
                    else "other"
                )
            )
            entries.append(
                {
                    "path": name,
                    "size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                    "kind": kind,
                }
            )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-archive-index",
        "archive": str(ap),
        "archive_sha256": hashlib.sha256(ap.read_bytes()).hexdigest(),
        "entries": entries,
        "source_file_count": sum(e["kind"] == "source" for e in entries),
        "metadata_file_count": sum(e["kind"] == "metadata" for e in entries),
    }
    out = Path(out_manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS",
        "manifest": str(out),
        "entries": len(entries),
        "source_file_count": payload["source_file_count"],
        "metadata_file_count": payload["metadata_file_count"],
        "archive_sha256": payload["archive_sha256"],
    }


def import_diversevul_jsonl(
    source_file: str | Path,
    out_manifest: str | Path,
    source_root: str | Path,
    cwe: str | None = None,
) -> dict[str, Any]:
    """Import DiverseVul JSON/JSONL while preserving target and commit provenance."""
    src = Path(source_file).resolve()
    root = Path(source_root).resolve()
    requested = _norm_cwe(cwe)
    rows = _read_rows(src)
    cases: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        code = _primevul_value(
            row, "func", "function", "code", "function_before", "processed_func"
        )
        if not isinstance(code, str) or not code.strip():
            continue
        raw_cwe = _primevul_value(row, "cwe", "CWE", "cwe_id", "CWE ID")
        if isinstance(raw_cwe, list):
            cwes = [x for x in (_norm_cwe(v) for v in raw_cwe) if x]
        else:
            one = _norm_cwe(raw_cwe)
            cwes = [one] if one else []
        if requested and requested not in cwes:
            continue
        label = _target_label(_primevul_value(row, "target", "label", "vulnerable"))
        rid = (
            _primevul_value(row, "id", "idx", "index", "sample_id")
            or f"diversevul-{idx:08d}"
        )
        project = _primevul_value(row, "project", "repo", "repository")
        commit = _primevul_value(row, "commit_id", "commit", "revision")
        commit_date = _primevul_value(row, "commit_date", "date", "timestamp")
        file_name = _primevul_value(row, "file_name", "file", "path")
        repo_url = _primevul_value(row, "project_url", "repo_url", "url")
        rec = {
            "id": f"diversevul-{rid}",
            "expected": label,
            "source": str(file_name) if file_name else None,
            "source_cwe": cwes,
            "partition": str(row.get("partition") or row.get("split") or "public"),
            "tags": ["real_corpus", "real_world", "diversevul"]
            + (
                ["positive"]
                if label == "MATCH"
                else ["negative"]
                if label == "NO_MATCH"
                else ["unknown"]
            ),
            "dimensions": ["real_corpus", "real_world"]
            + (["repository"] if project else [])
            + (["commit_provenance"] if commit else []),
            "label_provenance": {
                "authority": "DATASET",
                "source": "DiverseVul target field",
                "record_id": str(rid),
            },
            "case_identity": {
                "record_id": str(rid),
                "function_sha256": hashlib.sha256(
                    code.encode("utf-8", errors="replace")
                ).hexdigest(),
            },
            "dataset": {
                "name": "DiverseVul",
                "version": "2023-07-02",
                "record_id": str(rid),
                "repository": project,
                "project": project,
                "commit": commit,
                "commit_date": commit_date,
                "cwe": cwes,
                "file": file_name,
                "repository_url": repo_url,
                "label_source": "DiverseVul target field",
                "provenance_url": "https://github.com/wagner-group/diversevul",
                "source_root": str(root),
                "original_fields": row,
            },
            "source_content_sha256": hashlib.sha256(
                code.encode("utf-8", errors="replace")
            ).hexdigest(),
            "normalized_source_hash": _source_hashes(code)[1],
        }
        if file_name:
            fp = (root / str(file_name)).resolve()
            try:
                fp.relative_to(root)
                if fp.is_file():
                    rec["source_sha256"] = hashlib.sha256(fp.read_bytes()).hexdigest()
            except ValueError:
                rec["dataset"]["source_path_warning"] = (
                    "source escaped declared source_root"
                )
        if commit_date:
            rec["date"] = str(commit_date)
        cases.append(rec)
    return _write_manifest(
        out_manifest,
        {
            "name": "DiverseVul",
            "version": "2023-07-02",
            "source_file": str(src),
            "source_url": "https://github.com/wagner-group/diversevul",
            "label_policy": "explicit target field; preserve multi-CWE metadata",
        },
        cases,
    )


def import_sate6_directory(
    source_root: str | Path,
    out_manifest: str | Path,
    cwe: str | None = None,
    partition: str = "public",
) -> dict[str, Any]:
    """Import an extracted SATE6-style suite conservatively.

    SATE6 cases are often represented as buggy/fixed source pairs plus metadata. This
    importer recognizes explicit metadata files when present, and otherwise records
    source files as UNKNOWN rather than assuming a filename proves a label.
    """
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError(f"SATE6 root does not exist: {root}")
    requested = _norm_cwe(cwe)
    metadata_rows = []
    for name in (
        "manifest.json",
        "manifest.jsonl",
        "cases.json",
        "cases.jsonl",
        "metadata.json",
        "metadata.jsonl",
        "sard.csv",
        "metadata.csv",
    ):
        p = root / name
        if p.is_file():
            metadata_rows.extend(_read_rows(p))
            break
    cases = []
    if metadata_rows:
        for idx, row in enumerate(metadata_rows):
            cws = []
            raw_cwe = row.get("cwe") or row.get("CWE") or row.get("weakness")
            if isinstance(raw_cwe, list):
                cws = [_norm_cwe(x) for x in raw_cwe]
            elif raw_cwe:
                cws = [_norm_cwe(raw_cwe)]
            cws = [x for x in cws if x]
            if requested and requested not in cws:
                continue
            rel = (
                row.get("source")
                or row.get("file")
                or row.get("path")
                or row.get("bad_source")
                or row.get("vulnerable_source")
            )
            if not rel:
                continue
            sp = _archive_member_source(root, str(rel))
            if not sp:
                continue
            target = (
                row.get("expected")
                if row.get("expected") is not None
                else row.get("label") or row.get("state") or row.get("target")
            )
            expected = _target_label(target)
            repo = row.get("repository") or row.get("repo") or "Wireshark"
            commit = (
                row.get("commit")
                or row.get("revision")
                or row.get("fixed_commit")
                or row.get("bug_commit")
            )
            cve = row.get("cve") or row.get("CVE") or row.get("CVE ID")
            raw_sha, normalized_sha = _source_hashes(
                sp.read_text(encoding="utf-8", errors="replace")
            )
            case = {
                "id": str(row.get("id") or row.get("test_id") or f"sate6-{idx:06d}"),
                "expected": expected,
                "label_provenance": _label_provenance(
                    "DATASET",
                    "NIST SATE6 explicit metadata",
                    str(row.get("id") or row.get("test_id") or idx),
                ),
                "case_identity": {
                    "record_id": str(row.get("id") or row.get("test_id") or idx),
                    "repository": str(repo),
                    "commit": str(commit or ""),
                    "source_sha256": raw_sha,
                },
                "source_sha256": raw_sha,
                "normalized_source_hash": normalized_sha,
                "source": str(sp.relative_to(root)),
                "partition": partition,
                "tags": ["real_corpus", "real_world", "sate6"]
                + (
                    ["positive"]
                    if expected == "MATCH"
                    else ["negative"]
                    if expected == "NO_MATCH"
                    else ["unknown"]
                ),
                "dimensions": [
                    "real_corpus",
                    "real_world",
                    "repository",
                    "control_conditions",
                ]
                if row.get("control_flow")
                else ["real_corpus", "real_world", "repository"],
                "dataset": {
                    "name": "NIST SATE6 Wireshark 1.2",
                    "repository": repo,
                    "project": repo,
                    "commit": commit,
                    "cve": cve,
                    "cwe": cws,
                    "label_source": "explicit SATE6 metadata",
                    "provenance_url": "https://samate.nist.gov/SARD/test-suites/119",
                    "original_fields": row,
                },
            }
            cases.append(case)
    else:
        for idx, p in enumerate(sorted(root.rglob("*"))):
            if not p.is_file() or p.suffix.lower() not in C_EXTS:
                continue
            inferred = _infer_cwe(p.as_posix())
            if requested and inferred and inferred != requested:
                continue
            cases.append(
                {
                    "id": f"sate6-file-{idx:06d}",
                    "expected": "UNKNOWN",
                    "source": str(p.relative_to(root)),
                    "partition": partition,
                    "tags": ["real_corpus", "real_world", "sate6", "unknown"],
                    "dimensions": ["real_corpus", "real_world"],
                    "dataset": {
                        "name": "NIST SATE6 Wireshark 1.2",
                        "repository": "Wireshark",
                        "project": "Wireshark",
                        "label_source": "not assigned: no explicit metadata file was found",
                        "provenance_url": "https://samate.nist.gov/SARD/test-suites/119",
                    },
                }
            )
    return _write_manifest(
        out_manifest,
        {
            "name": "NIST SATE6 Wireshark 1.2",
            "provider": "NIST SAMATE",
            "kind": "real-world-plus-injected",
            "reference": "https://samate.nist.gov/SARD/test-suites/119",
            "sha256": "bd5f57d552467e6a2290ac1a1b474c276ac9c5813eecd441c61f4f34458170d2",
        },
        cases,
    )


def import_generic_records(
    source_file: str | Path,
    out_manifest: str | Path,
    source_root: str | Path,
    cwe: str | None = None,
    label_field: str = "expected",
) -> dict[str, Any]:
    """Generic, auditable JSON/JSONL/CSV -> dataset manifest adapter.

    Intended for research datasets with schema drift. Unknown/missing labels stay UNKNOWN.
    All original records are preserved under source_metadata.
    """
    src = Path(source_file).resolve()
    root = Path(source_root).resolve()
    requested = _norm_cwe(cwe)
    cases = []
    for idx, row in enumerate(_read_rows(src)):
        rawcwe = row.get("cwe") or row.get("CWE") or row.get("weakness")
        cws = (
            [_norm_cwe(x) for x in rawcwe]
            if isinstance(rawcwe, list)
            else [_norm_cwe(rawcwe)]
        )
        cws = [x for x in cws if x]
        if requested and requested not in cws:
            continue
        rel = (
            row.get("source")
            or row.get("source_path")
            or row.get("file")
            or row.get("file_path")
            or row.get("path")
        )
        code = (
            row.get("code")
            or row.get("func")
            or row.get("function")
            or row.get("function_code")
        )
        if rel:
            sp = _archive_member_source(root, str(rel))
            if not sp:
                continue
        elif isinstance(code, str) and code.strip():
            ext = ".c" if str(row.get("language", "")).lower() == "c" else ".cpp"
            tmp = root / ".evidencelab-imported"
            tmp.mkdir(parents=True, exist_ok=True)
            sp = tmp / (hashlib.sha256(f"{src}:{idx}".encode()).hexdigest()[:20] + ext)
            sp.write_text(
                code + "\n" if not code.endswith("\n") else code, encoding="utf-8"
            )
        else:
            continue
        expected = _target_label(
            row.get(label_field)
            if label_field in row
            else row.get("label") or row.get("target") or row.get("state")
        )
        try:
            code_text = sp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            code_text = ""
        raw_sha, normalized_sha = _source_hashes(code_text) if code_text else ("", "")
        ds = {
            "name": str(row.get("dataset") or src.stem),
            "repository": row.get("repository") or row.get("repo"),
            "project": row.get("project"),
            "commit": row.get("commit") or row.get("commit_id"),
            "cve": row.get("cve") or row.get("CVE ID"),
            "cwe": cws,
            "date": row.get("date") or row.get("commit_date"),
            "label_source": f"generic field mapping: {label_field}",
            "source_record_index": idx,
            "source_manifest": str(src),
        }
        tags = ["real_corpus"]
        dimensions = ["real_corpus"]
        if ds.get("repository"):
            dimensions += ["real_world", "repository"]
        if ds.get("project"):
            dimensions.append("project")
        if ds.get("cve"):
            dimensions.append("cve")
        rid = str(row.get("id") or row.get("case_id") or f"generic-{idx:07d}")
        cases.append(
            {
                "id": rid,
                "expected": expected,
                "label_provenance": _label_provenance(
                    "DATASET", f"generic field mapping: {label_field}", rid
                )
                if expected in {"MATCH", "NO_MATCH"}
                else {},
                "case_identity": {
                    "record_id": rid,
                    "source_sha256": raw_sha,
                    "normalized_source_hash": normalized_sha,
                },
                "source_sha256": raw_sha or None,
                "normalized_source_hash": normalized_sha or None,
                "source": str(sp.relative_to(root)),
                "partition": str(row.get("partition") or "public"),
                "tags": tags + (["real_world"] if ds.get("repository") else []),
                "dimensions": dimensions,
                "dataset": ds,
                "source_metadata": row,
            }
        )
    return _write_manifest(
        out_manifest,
        {"name": f"Generic import from {src.name}", "source_file": str(src)},
        cases,
    )
