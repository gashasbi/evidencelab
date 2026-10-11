from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, json, re


def normalized_source_hash(path: str | Path) -> str:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(text.encode()).hexdigest()


def source_inventory(root: str | Path) -> list[dict[str, Any]]:
    root = Path(root).resolve()
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in {
            ".c",
            ".h",
            ".cc",
            ".cpp",
            ".cxx",
            ".hpp",
        }:
            out.append(
                {
                    "path": str(p.relative_to(root)),
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                    "normalized_source_hash": normalized_source_hash(p),
                    "size": p.stat().st_size,
                }
            )
    return out


def tag_matrix(manifest: str | Path) -> dict[str, Any]:
    raw = json.loads(Path(manifest).read_text(encoding="utf-8"))
    cases = raw.get("cases", [])
    matrix = {}
    for c in cases:
        for tag in c.get("tags", []):
            d = matrix.setdefault(str(tag), {"total": 0, "expected": {}})
            d["total"] += 1
            e = str(c.get("expected", "UNKNOWN")).upper()
            d["expected"][e] = d["expected"].get(e, 0) + 1
    return {"case_count": len(cases), "tags": dict(sorted(matrix.items()))}


def split_manifest(
    manifest: str | Path,
    public_out: str | Path,
    hidden_out: str | Path,
    hidden_fraction: float = 0.2,
    seed: str = "evidencelab",
) -> dict[str, Any]:
    if not 0.0 < hidden_fraction < 1.0:
        raise ValueError("hidden_fraction must be between 0 and 1")
    p = Path(manifest).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    cases = list(raw.get("cases", []))
    ranked = sorted(
        cases,
        key=lambda c: hashlib.sha256(
            (seed + ":" + str(c.get("id"))).encode()
        ).hexdigest(),
    )
    hidden_n = (
        max(1, min(len(cases) - 1, round(len(cases) * hidden_fraction)))
        if len(cases) > 1
        else 0
    )
    hidden = ranked[:hidden_n]
    public = ranked[hidden_n:]
    pub = dict(raw)
    pub["manifest_id"] = str(raw.get("manifest_id", p.stem)) + "-public"
    pub["partition"] = "public"
    pub["cases"] = public
    hid = dict(raw)
    hid["manifest_id"] = str(raw.get("manifest_id", p.stem)) + "-hidden"
    hid["partition"] = "hidden"
    hid["cases"] = [dict(x, partition="hidden") for x in hidden]
    po = Path(public_out)
    ho = Path(hidden_out)
    po.parent.mkdir(parents=True, exist_ok=True)
    ho.parent.mkdir(parents=True, exist_ok=True)
    po.write_text(
        json.dumps(pub, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    ho.write_text(
        json.dumps(hid, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "public": len(public),
        "hidden": len(hidden),
        "public_path": str(po),
        "hidden_path": str(ho),
        "seed": seed,
    }
