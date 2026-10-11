from __future__ import annotations
from . import SCHEMA_VERSION

from pathlib import Path
from typing import Any
import hashlib
import json
import subprocess

EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}


def _git(repo: Path, *args: str) -> str:
    p = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "git command failed")
    return p.stdout


def build_commit_pair(
    repo: str | Path,
    fixed_commit: str,
    cwe: str,
    out: str | Path,
    cve: str | None = None,
) -> dict[str, Any]:
    """Materialize a bug-fix commit as a paired before/after research dataset.

    The parent revision is the vulnerable side by default and the fixed revision is
    the counterfactual safe side. The output contains both a pair-specific record and
    a normal EvidenceLab dataset manifest so it can flow into capture/evaluation tools.
    """
    r = Path(repo).resolve()
    outp = Path(out).resolve()
    outp.mkdir(parents=True, exist_ok=True)
    parent = _git(r, "rev-parse", f"{fixed_commit}^").strip()
    fixed = _git(r, "rev-parse", fixed_commit).strip()
    try:
        remote = _git(r, "config", "--get", "remote.origin.url").strip()
    except RuntimeError:
        remote = None
    parent_date = _git(r, "show", "-s", "--format=%cI", parent).strip()
    fixed_date = _git(r, "show", "-s", "--format=%cI", fixed).strip()
    changed = [
        x.strip()
        for x in _git(r, "diff", "--name-only", parent, fixed, "--").splitlines()
        if Path(x).suffix.lower() in EXTS
    ]
    if not changed:
        raise RuntimeError("no C/C++ files changed between commits")

    pairs: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for rel in changed:
        try:
            before = _git(r, "show", f"{parent}:{rel}")
            after = _git(r, "show", f"{fixed}:{rel}")
        except RuntimeError:
            # Handle a newly-added/deleted C/C++ file conservatively.
            continue
        key = hashlib.sha256(f"{fixed}|{rel}".encode()).hexdigest()[:20]
        before_path = outp / "before" / f"{key}{Path(rel).suffix or '.txt'}"
        after_path = outp / "after" / f"{key}{Path(rel).suffix or '.txt'}"
        before_path.parent.mkdir(parents=True, exist_ok=True)
        after_path.parent.mkdir(parents=True, exist_ok=True)
        before_path.write_text(before, encoding="utf-8")
        after_path.write_text(after, encoding="utf-8")
        before_sha = hashlib.sha256(before.encode("utf-8")).hexdigest()
        after_sha = hashlib.sha256(after.encode("utf-8")).hexdigest()
        pair_id = f"pair-{key}"
        common = {
            "name": "git-commit-pair",
            "repository": remote or str(r),
            "project": r.name,
            "vulnerable_commit": parent,
            "fixed_commit": fixed,
            "vulnerable_commit_date": parent_date,
            "fixed_commit_date": fixed_date,
            "commit": parent,
            "cwe": cwe.upper(),
            "cve": cve,
            "file": rel,
            "label_source": "commit parent/fixed revision relationship",
            "pair_id": pair_id,
        }
        before_id = f"{pair_id}:before"
        after_id = f"{pair_id}:after"
        before_case = {
            "id": before_id,
            "expected": "MATCH",
            "source": str(before_path.relative_to(outp)),
            "partition": "public",
            "tags": [
                "real_world",
                "real_corpus",
                "commit_pair",
                "vulnerable_revision",
                "positive",
            ],
            "dimensions": [
                "real_world",
                "real_corpus",
                "provenance",
                "repository",
                "project",
                "cve",
                "patch_context",
            ],
            "dataset": dict(
                common,
                revision_role="vulnerable",
                revision=parent,
                date=parent_date,
                commit_date=parent_date,
                source_url=remote,
            ),
            "counterpart": after_id,
            "pair_id": pair_id,
            "label_provenance": {
                "authority": "PATCH_BASED",
                "source": f"{remote or r}::{fixed}",
                "record_id": pair_id,
                "rationale": "parent revision is vulnerable side of a documented fixed commit",
            },
            "case_identity": {
                "pair_id": pair_id,
                "revision": parent,
                "file": rel,
                "source_sha256": before_sha,
            },
            "source_sha256": before_sha,
            "source_content_sha256": before_sha,
        }
        after_case = {
            "id": after_id,
            "expected": "NO_MATCH",
            "source": str(after_path.relative_to(outp)),
            "partition": "public",
            "tags": [
                "real_world",
                "real_corpus",
                "commit_pair",
                "fixed_revision",
                "negative",
            ],
            "dimensions": [
                "real_world",
                "real_corpus",
                "provenance",
                "repository",
                "project",
                "cve",
                "patch_context",
            ],
            "dataset": dict(
                common,
                revision_role="fixed",
                revision=fixed,
                commit=fixed,
                date=fixed_date,
                commit_date=fixed_date,
                source_url=remote,
            ),
            "counterpart": before_id,
            "pair_id": pair_id,
            "label_provenance": {
                "authority": "PATCH_BASED",
                "source": f"{remote or r}::{fixed}",
                "record_id": pair_id,
                "rationale": "fixed revision is the post-fix counterfactual side of the same patch pair",
            },
            "case_identity": {
                "pair_id": pair_id,
                "revision": fixed,
                "file": rel,
                "source_sha256": after_sha,
            },
            "source_sha256": after_sha,
            "source_content_sha256": after_sha,
        }
        cases.extend([before_case, after_case])
        pairs.append(
            {
                "pair_id": pair_id,
                "path": rel,
                "before": str(before_path.relative_to(outp)),
                "after": str(after_path.relative_to(outp)),
                "before_case": before_id,
                "after_case": after_id,
                "repository": remote or str(r),
                "vulnerable_commit": parent,
                "fixed_commit": fixed,
            }
        )

    if not pairs:
        raise RuntimeError("no readable C/C++ before/after file pairs were produced")

    pair_payload = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-git-pair-dataset",
        "cwe": cwe.upper(),
        "cve": cve,
        "repository": str(r),
        "project": r.name,
        "vulnerable_commit": parent,
        "fixed_commit": fixed,
        "vulnerable_commit_date": parent_date,
        "fixed_commit_date": fixed_date,
        "remote": remote,
        "case_count": len(cases),
        "pairs": pairs,
    }
    pairs_file = outp / "pairs.json"
    pairs_file.write_text(
        json.dumps(pair_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-dataset-manifest",
        "dataset": {
            "name": "Git commit vulnerability pairs",
            "type": "before_after_patch_pair",
            "repository": remote or str(r),
            "project": r.name,
            "vulnerable_commit": parent,
            "fixed_commit": fixed,
            "cwe": cwe.upper(),
            "cve": cve,
            "provenance": "local git repository",
        },
        "case_count": len(cases),
        "cases": cases,
    }
    manifest_file = outp / "dataset-manifest.json"
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS",
        "case_count": len(cases),
        "pair_count": len(pairs),
        "vulnerable_commit": parent,
        "fixed_commit": fixed,
        "vulnerable_commit_date": parent_date,
        "fixed_commit_date": fixed_date,
        "remote": remote,
        "pairs": str(pairs_file),
        "manifest": str(manifest_file),
    }
