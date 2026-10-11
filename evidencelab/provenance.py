from __future__ import annotations
from . import SCHEMA_VERSION
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import hashlib, json, os, platform, subprocess, sys, time


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def git_info(root: str | Path) -> dict[str, Any]:
    cwd = str(Path(root).resolve())
    info: dict[str, Any] = {"repository": False}
    try:
        ok = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if ok.returncode != 0 or ok.stdout.strip() != "true":
            return info
        info["repository"] = True
        for key, args in {
            "commit": ["rev-parse", "HEAD"],
            "branch": ["branch", "--show-current"],
            "dirty": ["status", "--porcelain=v1"],
        }.items():
            p = subprocess.run(
                ["git", "-C", cwd, *args], capture_output=True, text=True, timeout=5
            )
            if p.returncode == 0:
                value = p.stdout.strip()
                info[key] = bool(value) if key == "dirty" else value
    except Exception as exc:
        info["error"] = str(exc)
    return info


def environment_snapshot(root: str | Path | None = None) -> dict[str, Any]:
    snap = {
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cwd": os.getcwd(),
    }
    if root is not None:
        snap["git"] = git_info(root)
    return snap


@dataclass(slots=True)
class ProvenanceRecord:
    id: str
    kind: str
    activity: str
    agent: str
    inputs: list[str]
    outputs: list[str]
    parameters: dict[str, Any]
    timestamp_utc: str
    previous: str | None = None
    digest: str | None = None

    def finalize(self) -> "ProvenanceRecord":
        body = asdict(self)
        body["digest"] = None
        self.digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        return self


def build_provenance_manifest(
    root: str | Path,
    files: list[str | Path] | None = None,
    out: str | Path | None = None,
    activity: str = "artifact-index",
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    selected = (
        [Path(x).resolve() for x in files]
        if files
        else [p for p in rootp.rglob("*") if p.is_file() and ".git" not in p.parts]
    )
    selected = sorted({p for p in selected if p.is_file()})
    artifacts = []
    for p in selected:
        try:
            rel = str(p.relative_to(rootp))
        except ValueError:
            rel = str(p)
        artifacts.append(
            {"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size}
        )
    env = environment_snapshot(rootp)
    rec = ProvenanceRecord(
        id=f"prov-{int(time.time())}",
        kind="activity",
        activity=activity,
        agent="EvidenceLab",
        inputs=[x["path"] for x in artifacts],
        outputs=["provenance.json"],
        parameters={},
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    ).finalize()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "root": str(rootp),
        "environment": env,
        "artifacts": artifacts,
        "provenance": [asdict(rec)],
    }
    payload["manifest_sha256"] = sha256_json(payload)
    if out:
        op = Path(out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return payload


def verify_artifact_manifest(manifest_path: str | Path) -> dict[str, Any]:
    p = Path(manifest_path).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    root = Path(raw["root"]).resolve()
    errors: list[str] = []
    checked = 0
    for item in raw.get("artifacts", []):
        target = (root / str(item["path"])).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            errors.append(f"artifact escapes root: {item['path']}")
            continue
        if not target.is_file():
            errors.append(f"missing artifact: {item['path']}")
            continue
        checked += 1
        actual = sha256_file(target)
        if actual != item.get("sha256"):
            errors.append(f"sha256 mismatch: {item['path']}")
    body = dict(raw)
    expected_manifest = body.pop("manifest_sha256", None)
    actual_manifest = sha256_json(body)
    if expected_manifest and expected_manifest != actual_manifest:
        errors.append("manifest_sha256 mismatch")
    return {
        "status": "PASS" if not errors else "FAIL",
        "checked": checked,
        "errors": errors,
    }
