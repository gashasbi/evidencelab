from __future__ import annotations
from . import SCHEMA_VERSION
from pathlib import Path
from typing import Any
import json, time, uuid
from .provenance import environment_snapshot, sha256_json


def record_experiment(
    root: str | Path,
    hypothesis: str,
    tool: str,
    command: str,
    result: str,
    cases: list[str] | None = None,
    parameters: dict[str, Any] | None = None,
    observations: list[str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    log = rootp / "experiments" / "experiment-ledger.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    prior = None
    if log.exists():
        lines = log.read_text(encoding="utf-8").splitlines()
        if lines:
            try:
                prior = json.loads(lines[-1]).get("digest")
            except Exception:
                pass
    payload = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": f"exp-{uuid.uuid4().hex[:12]}",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hypothesis": hypothesis,
        "tool": tool,
        "command": command,
        "result": result,
        "cases": cases or [],
        "parameters": parameters or {},
        "observations": observations or [],
        "notes": notes,
        "environment": environment_snapshot(rootp),
        "previous": prior,
    }
    payload["digest"] = sha256_json(payload)
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    return payload


def audit_experiment_ledger(root: str | Path) -> dict[str, Any]:
    p = Path(root).resolve() / "experiments" / "experiment-ledger.jsonl"
    errors = []
    count = 0
    prev = None
    if not p.is_file():
        return {
            "status": "FAIL",
            "errors": ["experiment-ledger.jsonl missing"],
            "count": 0,
        }
    for line_no, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            x = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"line {line_no}: invalid JSON: {e}")
            continue
        expected = x.get("digest")
        body = dict(x)
        body.pop("digest", None)
        if expected != sha256_json(body):
            errors.append(f"line {line_no}: digest mismatch")
        if prev is not None and x.get("previous") != prev:
            errors.append(f"line {line_no}: broken chain")
        prev = expected
        count += 1
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "count": count,
        "head": prev,
    }
