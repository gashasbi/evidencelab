#!/usr/bin/env python3
"""Create a source-safe census and integrity audit for an imported dataset manifest.

This complements EvidenceLab's dataset-validate command; it does not assign labels,
claim scientific validity, execute source code, or replace benchmark quality gates.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

KNOWN = {"MATCH", "NO_MATCH", "UNKNOWN"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_under_manifest(manifest: Path, value: str) -> Path:
    p = Path(value).expanduser()
    return (p if p.is_absolute() else manifest.parent / p).resolve()


def audit(
    path: Path,
    *,
    verify_sources: bool = False,
    allowed_source_roots: list[Path] | None = None,
) -> dict[str, Any]:
    path = path.resolve()
    trusted_roots = [path.parent] + [Path(x).expanduser().resolve() for x in (allowed_source_roots or [])]
    raw = json.loads(path.read_text(encoding="utf-8"))
    cases = raw.get("cases")
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(cases, list):
        return {"status": "FAIL", "manifest": path.name, "errors": ["cases is not an array"], "warnings": []}

    if not cases:
        errors.append("cases array is empty; no research corpus can be formed")

    labels: Counter[str] = Counter()
    ids: Counter[str] = Counter()
    repositories: set[str] = set()
    projects: set[str] = set()
    datasets: set[str] = set()
    cves: set[str] = set()
    source_hashes: dict[str, list[dict[str, str]]] = defaultdict(list)
    source_present = source_missing = source_checked = source_mismatch = 0
    missing_identity: list[str] = []
    missing_label_provenance: list[str] = []
    missing_source_hash: list[str] = []
    missing_timestamp: list[str] = []
    invalid_rows: list[str] = []
    mutation_count = 0

    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            invalid_rows.append(f"row-{index}: not an object")
            continue
        cid = str(case.get("id") or f"row-{index}")
        if not case.get("id"):
            errors.append(f"row-{index}: case id is missing")
        ids[cid] += 1
        expected = str(case.get("expected", "UNKNOWN")).upper()
        labels[expected] += 1
        if expected not in KNOWN:
            errors.append(f"{cid}: unexpected label {expected}")
        if case.get("mutation_of") or case.get("mutation_parent") or case.get("mutation"):
            mutation_count += 1

        dataset = case.get("dataset") if isinstance(case.get("dataset"), dict) else {}
        raw_dataset = raw.get("dataset") if isinstance(raw.get("dataset"), dict) else {}
        name = dataset.get("name") or raw_dataset.get("name")
        if name:
            datasets.add(str(name))
        repo = dataset.get("repository") or dataset.get("repo")
        project = dataset.get("project")
        if repo:
            repositories.add(str(repo))
        if project:
            projects.add(str(project))
        raw_cves = dataset.get("cve") or dataset.get("CVE ID") or case.get("cve")
        for cv in (raw_cves if isinstance(raw_cves, list) else [raw_cves]):
            if cv:
                cves.add(str(cv))
        stable_id = (case.get("case_identity") or {}).get("record_id") if isinstance(case.get("case_identity"), dict) else None
        if not (stable_id or case.get("source_sha256") or case.get("source_content_sha256") or dataset.get("record_id")):
            missing_identity.append(cid)
        if expected in {"MATCH", "NO_MATCH"}:
            provenance = case.get("label_provenance") if isinstance(case.get("label_provenance"), dict) else {}
            if not (provenance.get("source") or case.get("label_source") or dataset.get("label_source")):
                missing_label_provenance.append(cid)
        source_ref = case.get("source")
        if source_ref:
            source_path = resolve_under_manifest(path, str(source_ref))
            try:
                source_path.relative_to(trusted_roots[0])
                source_is_trusted = True
            except ValueError:
                source_is_trusted = False
                for trusted_root in trusted_roots[1:]:
                    try:
                        source_path.relative_to(trusted_root)
                        source_is_trusted = True
                        break
                    except ValueError:
                        continue
            if not source_is_trusted:
                errors.append(f"{cid}: source path escapes the declared trusted roots")
                source_missing += 1
                continue
            if source_path.is_file():
                source_present += 1
                recorded_hash = case.get("source_sha256") or case.get("source_content_sha256")
                if recorded_hash:
                    source_hashes[str(recorded_hash)].append({"id": cid, "label": expected})
                else:
                    missing_source_hash.append(cid)
                if verify_sources and recorded_hash:
                    source_checked += 1
                    if sha256(source_path) != str(recorded_hash):
                        source_mismatch += 1
                        errors.append(f"{cid}: source hash mismatch")
            else:
                source_missing += 1
                warnings.append(f"{cid}: source file is not available at the declared path")
        else:
            missing_source_hash.append(cid)
        if not (dataset.get("date") or dataset.get("commit_date") or case.get("date") or case.get("commit_date")):
            missing_timestamp.append(cid)

    duplicates = sorted(cid for cid, count in ids.items() if count > 1)
    if duplicates:
        errors.append(f"duplicate case ids: {len(duplicates)}")
    contradictory_source_hashes = []
    duplicate_source_groups_detail = []
    for digest, rows in source_hashes.items():
        if len(rows) > 1:
            row_labels = sorted({row["label"] for row in rows})
            duplicate_source_groups_detail.append({"sha256": digest, "case_ids": [x["id"] for x in rows], "labels": row_labels})
            if len(row_labels) > 1:
                contradictory_source_hashes.append({"sha256": digest, "case_ids": [x["id"] for x in rows], "labels": row_labels})
    duplicate_source_groups = len(duplicate_source_groups_detail)
    if duplicate_source_groups_detail:
        warnings.append(f"exact source-content reuse found in {len(duplicate_source_groups_detail)} hash groups; inspect group identity and split placement")
    if contradictory_source_hashes:
        errors.append("identical source hashes have conflicting labels")
    if invalid_rows:
        errors.append(f"non-object case records: {len(invalid_rows)}")
    if missing_identity:
        warnings.append(f"stable source/record identity missing on {len(missing_identity)} cases")
    if missing_label_provenance:
        warnings.append(f"known-label provenance missing on {len(missing_label_provenance)} cases")
    if missing_source_hash:
        warnings.append(f"source hash missing or source path unavailable on {len(missing_source_hash)} cases")
    if missing_timestamp:
        warnings.append(f"commit/date metadata missing on {len(missing_timestamp)} cases; chronological split may be unavailable")
    if not source_present:
        warnings.append("no source files resolved relative to the manifest; graph-only evaluation may still be possible")
    if source_mismatch:
        errors.append(f"source hash mismatches: {source_mismatch}")

    # Public report is intentionally metadata-only; it never serializes function source.
    return {
        "status": "FAIL" if errors else "PASS",
        "manifest": path.name,
        "format": raw.get("format"),
        "dataset": raw.get("dataset", {}).get("name") if isinstance(raw.get("dataset"), dict) else None,
        "case_count": len(cases),
        "label_counts": {k: labels.get(k, 0) for k in ("MATCH", "NO_MATCH", "UNKNOWN")},
        "other_label_count": sum(v for k, v in labels.items() if k not in KNOWN),
        "independent_case_count_excluding_declared_mutations": len(cases) - mutation_count,
        "declared_mutation_count": mutation_count,
        "dataset_count": len(datasets),
        "repository_count": len(repositories),
        "project_count": len(projects),
        "cve_count": len(cves),
        "source_files_found": source_present,
        "source_files_missing": source_missing,
        "source_hashes_verified": source_checked,
        "source_hash_mismatches": source_mismatch,
        "duplicate_source_hash_groups": duplicate_source_groups,
        "duplicate_source_hash_groups_detail": duplicate_source_groups_detail[:100],
        "contradictory_source_hashes": contradictory_source_hashes[:100],
        "missing_stable_identity_count": len(missing_identity),
        "missing_known_label_provenance_count": len(missing_label_provenance),
        "missing_source_hash_count": len(missing_source_hash),
        "missing_date_count": len(missing_timestamp),
        "errors": errors,
        "warnings": warnings,
        "policy_note": "This is a metadata/integrity census, not an assessment of label truth or publication readiness.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--verify-source-hashes", action="store_true")
    parser.add_argument("--allowed-source-root", type=Path, action="append", default=[], help="additional trusted source roots; may be repeated")
    args = parser.parse_args()
    try:
        result = audit(
            args.manifest,
            verify_sources=args.verify_source_hashes,
            allowed_source_roots=args.allowed_source_root,
        )
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}, indent=2), file=sys.stderr)
        return 2
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
