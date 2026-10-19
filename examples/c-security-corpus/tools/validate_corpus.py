#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()

def main():
    manifest = json.loads((ROOT / "metadata/manifest.json").read_text())
    errors = []
    samples = manifest["samples"]
    ids, paths = set(), set()

    for item in samples:
        sid, rel, label = item.get("id"), item.get("file"), item.get("label")
        if not sid or sid in ids:
            errors.append(f"missing/duplicate id: {sid}")
        ids.add(sid)
        if not rel or rel in paths:
            errors.append(f"missing/duplicate path: {rel}")
        paths.add(rel)
        if label not in {"VULN", "SAFE", "UNKNOWN"}:
            errors.append(f"{sid}: invalid label {label}")
        p = (ROOT / rel).resolve()
        if ROOT.resolve() not in p.parents:
            errors.append(f"{sid}: path escapes corpus root")
        elif not p.is_file():
            errors.append(f"{sid}: missing file {rel}")
        elif not p.read_text(encoding="utf-8").startswith(
                "/* EvidenceLab synthetic corpus"):
            errors.append(f"{sid}: missing header")

    if manifest.get("sample_count") != len(samples):
        errors.append("manifest sample_count mismatch")

    if errors:
        print("FAIL")
        print("\n".join("- " + e for e in errors))
        return 1

    print(f"PASS: {len(samples)} samples; {len(set(s['cwe'] for s in samples))} CWE families")
    return 0

if __name__ == "__main__":
    sys.exit(main())
