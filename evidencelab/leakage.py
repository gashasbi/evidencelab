from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, json, re

TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|==|!=|<=|>=|->|&&|\|\||[^\s]"
)


def normalize_code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(normalize_code(text))


def _shingles(toks: list[str], ngram: int = 5) -> set[str]:
    if not toks:
        return set()
    if len(toks) <= ngram:
        return {" ".join(toks)}
    return {" ".join(toks[i : i + ngram]) for i in range(len(toks) - ngram + 1)}


def fingerprint(text: str, ngram: int = 5) -> str:
    shingles = _shingles(tokens(text), ngram)
    return hashlib.sha256("\n".join(sorted(shingles)).encode("utf-8")).hexdigest()


def _simhash(text: str, ngram: int = 5) -> int:
    shingles = _shingles(tokens(text), ngram)
    if not shingles:
        return 0
    acc = [0] * 64
    for shingle in shingles:
        value = int.from_bytes(
            hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for bit in range(64):
            acc[bit] += 1 if (value >> bit) & 1 else -1
    result = 0
    for bit, score in enumerate(acc):
        if score >= 0:
            result |= 1 << bit
    return result


def _hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def jaccard_similarity(a: str, b: str, ngram: int = 5) -> float:
    aa = _shingles(tokens(a), ngram)
    bb = _shingles(tokens(b), ngram)
    if not aa and not bb:
        return 1.0
    if not aa or not bb:
        return 0.0
    return len(aa & bb) / len(aa | bb)


def audit_source_files(
    paths: list[str | Path],
    similarity_threshold: float = 0.92,
    max_comparisons: int = 250_000,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    by_exact: dict[str, list[int]] = {}
    texts: dict[int, str] = {}
    bands: dict[tuple[int, int], list[int]] = {}
    for i, p0 in enumerate(paths):
        p = Path(p0).resolve()
        text = p.read_text(encoding="utf-8", errors="replace")
        texts[i] = text
        normalized = normalize_code(text)
        sim = _simhash(text)
        record = {
            "path": str(p),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "normalized_hash": hashlib.sha256(normalized.encode()).hexdigest(),
            "fingerprint": fingerprint(text),
            "simhash": f"{sim:016x}",
            "size": len(text),
            "token_count": len(tokens(text)),
        }
        records.append(record)
        by_exact.setdefault(record["normalized_hash"], []).append(i)
        for band in range(4):
            key = (band, (sim >> (band * 16)) & 0xFFFF)
            bands.setdefault(key, []).append(i)

    exact_groups = [
        [records[i]["path"] for i in ids] for ids in by_exact.values() if len(ids) > 1
    ]
    candidates: set[tuple[int, int]] = set()
    truncated = False
    for ids in bands.values():
        if len(ids) < 2:
            continue
        ids = sorted(set(ids))
        for pos, i in enumerate(ids[:-1]):
            for j in ids[pos + 1 :]:
                pair = (i, j)
                if pair in candidates:
                    continue
                if len(candidates) >= max_comparisons:
                    truncated = True
                    break
                candidates.add(pair)
            if truncated:
                break
        if truncated:
            break

    near = []
    for i, j in sorted(candidates):
        if records[i]["normalized_hash"] == records[j]["normalized_hash"]:
            continue
        sim = jaccard_similarity(texts[i], texts[j])
        if sim >= similarity_threshold:
            near.append(
                {
                    "a": records[i]["path"],
                    "b": records[j]["path"],
                    "jaccard": round(sim, 6),
                    "simhash_hamming": _hamming(
                        int(records[i]["simhash"], 16), int(records[j]["simhash"], 16)
                    ),
                }
            )
    status = "FAIL" if truncated else ("WARN" if exact_groups or near else "PASS")
    return {
        "status": status,
        "files": len(records),
        "exact_duplicate_groups": exact_groups,
        "near_duplicates": near,
        "similarity_threshold": similarity_threshold,
        "candidate_comparisons": len(candidates),
        "max_comparisons": max_comparisons,
        "comparison_truncated": truncated,
        "algorithm": "exact-normalized-hash + 4-band SimHash LSH candidate search",
        "records": records,
    }


def audit_benchmark_lineage(manifest: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(manifest).read_text(encoding="utf-8"))
    cases = raw.get("cases", [])
    by_parent: dict[str, list[str]] = {}
    errors: list[str] = []
    ids = {str(c.get("id")) for c in cases}
    for c in cases:
        parent = c.get("mutation_of")
        if parent:
            by_parent.setdefault(str(parent), []).append(str(c.get("id")))
    for parent, children in by_parent.items():
        if parent not in ids:
            errors.append(f"mutation parent missing: {parent}")
        if len(children) > 50:
            errors.append(
                f"mutation fanout unusually high for {parent}: {len(children)}"
            )
    return {
        "status": "PASS" if not errors else "FAIL",
        "parents": len(by_parent),
        "mutation_cases": sum(map(len, by_parent.values())),
        "errors": errors,
    }


def audit_case_lineage_and_similarity(
    cases: list[dict[str, Any]], *, similarity_threshold: float = 0.92
) -> dict[str, Any]:
    """Audit case-level lineage identity without treating mutations as independent data."""
    errors: list[str] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    for case in cases:
        cid = str(case.get("id", ""))
        if not cid:
            continue
        if cid in seen_ids:
            errors.append(f"duplicate case id: {cid}")
        seen_ids.add(cid)
        parent = case.get("mutation_of") or case.get("mutation_parent")
        if parent and str(parent) == cid:
            errors.append(f"self mutation lineage: {cid}")
        pair = case.get("pair_id") or (case.get("dataset") or {}).get("pair_id")
        if pair and case.get("expected") == "MATCH" and not case.get("counterpart"):
            warnings.append(
                f"paired case {cid} has no explicit counterpart; do not assume fixed revision semantics"
            )

    by_hash: dict[str, list[str]] = {}
    for case in cases:
        h = case.get("normalized_source_hash") or (
            case.get("source_metadata") or {}
        ).get("normalized_source_hash")
        if h:
            by_hash.setdefault(str(h), []).append(str(case.get("id")))
    exact_groups = [ids for ids in by_hash.values() if len(ids) > 1]
    if exact_groups:
        warnings.append(f"{len(exact_groups)} exact normalized-source groups detected")
    return {
        "status": "FAIL" if errors else ("WARN" if warnings else "PASS"),
        "errors": errors,
        "warnings": warnings,
        "exact_normalized_source_groups": exact_groups,
    }
