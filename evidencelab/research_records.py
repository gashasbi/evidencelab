from __future__ import annotations
from . import SCHEMA_VERSION

from pathlib import Path
from typing import Any
import json
import time
import uuid

from .outcomes import normalize_proof_state
from .provenance import sha256_json


def _append(root: Path, name: str, payload: dict[str, Any]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    previous = None
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines()[::-1]:
            if line.strip():
                try:
                    previous = json.loads(line).get("digest")
                except Exception:
                    previous = None
                break
    payload = dict(payload)
    payload["previous"] = previous
    payload["digest"] = sha256_json(payload)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def record_observation(
    root: str | Path,
    *,
    observation_id: str | None,
    hypothesis_id: str | None,
    analyzer: str,
    query: str,
    artifact: str,
    statement: str,
    state: str = "OBSERVED",
    locations: list[dict[str, Any]] | None = None,
    raw_digest: str | None = None,
    notes: str = "",
    capability_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one immutable raw observation.

    Observations describe analyzer output, not semantic conclusions. They therefore never
    require a prior EvidenceLab derivation, but must identify the source artifact/query.
    """
    if (
        not analyzer.strip()
        or not query.strip()
        or not artifact.strip()
        or not statement.strip()
    ):
        raise ValueError(
            "observation analyzer, query, artifact and statement are required"
        )
    rootp = Path(root).resolve() / "experiments"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "RAW_OBSERVATION",
        "observation_id": observation_id or f"obs-{uuid.uuid4().hex[:12]}",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hypothesis_id": hypothesis_id,
        "analyzer": analyzer,
        "query": query,
        "artifact": artifact,
        "statement": statement,
        "state": normalize_proof_state(state, default="UNKNOWN"),
        "locations": locations or [],
        "raw_digest": raw_digest,
        "capability_snapshot": capability_snapshot or {},
        "notes": notes,
    }
    path = _append(rootp, "observations.jsonl", payload)
    payload["ledger_path"] = str(path)
    return payload


def record_derivation(
    root: str | Path,
    *,
    derivation_id: str | None,
    hypothesis_id: str | None,
    method: str,
    inputs: list[str],
    output: dict[str, Any],
    assumptions: list[str] | None = None,
    state: str = "PROVEN",
    evidence_definition: str | None = None,
    replay: dict[str, Any] | None = None,
    notes: str = "",
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Append a semantic derivation with explicit input lineage.

    Definitive derivations cannot be created without at least one observation/artifact input.
    """
    if not method.strip() or not isinstance(output, dict):
        raise ValueError("derivation method and object output are required")
    inputs = [str(x) for x in inputs if str(x).strip()]
    state_norm = normalize_proof_state(state)
    if state_norm in {"PROVEN", "DISPROVEN"} and not inputs and not provenance:
        raise ValueError("definitive derivation requires inputs or explicit provenance")
    rootp = Path(root).resolve() / "experiments"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "DERIVATION",
        "derivation_id": derivation_id or f"der-{uuid.uuid4().hex[:12]}",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hypothesis_id": hypothesis_id,
        "method": method,
        "inputs": inputs,
        "output": output,
        "assumptions": assumptions or [],
        "state": state_norm,
        "evidence_definition": evidence_definition,
        "replay": replay or {},
        "provenance": provenance or [],
        "notes": notes,
    }
    path = _append(rootp, "derivations.jsonl", payload)
    payload["ledger_path"] = str(path)
    return payload


def _audit_chain(
    path: Path, allowed_versions: set[str]
) -> tuple[list[str], int, str | None, list[dict[str, Any]]]:
    errors: list[str] = []
    records: list[dict[str, Any]] = []
    previous = None
    if not path.is_file():
        return [], 0, None, []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            x = json.loads(line)
        except Exception as exc:
            errors.append(f"{path.name}:{lineno}: invalid JSON: {exc}")
            continue
        records.append(x)
        digest = x.get("digest")
        body = dict(x)
        body.pop("digest", None)
        if digest != sha256_json(body):
            errors.append(f"{path.name}:{lineno}: digest mismatch")
        if previous is not None and x.get("previous") != previous:
            errors.append(f"{path.name}:{lineno}: broken hash chain")
        if str(x.get("schema_version")) not in allowed_versions:
            errors.append(
                f"{path.name}:{lineno}: unsupported schema_version {x.get('schema_version')}"
            )
        previous = digest
    return errors, len(records), previous, records


def audit_research_ledgers(
    root: str | Path, *, require_nonempty: bool = False
) -> dict[str, Any]:
    rootp = Path(root).resolve() / "experiments"
    errors: list[str] = []
    reports: dict[str, Any] = {}
    obs_errors, obs_count, obs_head, observations = _audit_chain(
        rootp / "observations.jsonl", {SCHEMA_VERSION}
    )
    der_errors, der_count, der_head, derivations = _audit_chain(
        rootp / "derivations.jsonl", {SCHEMA_VERSION}
    )
    errors.extend(obs_errors + der_errors)
    if require_nonempty and (obs_count == 0 or der_count == 0):
        errors.append("research ledger requires non-empty observations and derivations")

    observation_ids = {
        str(x.get("observation_id")) for x in observations if x.get("observation_id")
    }
    derivation_ids = {
        str(x.get("derivation_id")) for x in derivations if x.get("derivation_id")
    }
    known_artifacts = {
        str(x.get("artifact")) for x in observations if x.get("artifact")
    }
    for item in derivations:
        state = str(item.get("state", "UNKNOWN")).upper()
        inputs = [str(x) for x in item.get("inputs", [])]
        prov = (
            item.get("provenance") if isinstance(item.get("provenance"), list) else []
        )
        if state in {"PROVEN", "DISPROVEN"} and not inputs and not prov:
            errors.append(
                f"derivations.jsonl:{item.get('derivation_id')}: definitive derivation has no provenance"
            )
        for ref in inputs:
            if (
                ref not in observation_ids
                and ref not in derivation_ids
                and ref not in known_artifacts
                and not ref.startswith(
                    ("graph:", "artifact:", "query:", "dataset:", "literature:")
                )
            ):
                errors.append(
                    f"derivations.jsonl:{item.get('derivation_id')}: unresolved input {ref}"
                )
        replay = item.get("replay") or {}
        if (
            state in {"PROVEN", "DISPROVEN"}
            and replay
            and replay.get("status") not in {"PASS", "VERIFIED"}
        ):
            errors.append(
                f"derivations.jsonl:{item.get('derivation_id')}: definitive derivation replay is not verified"
            )

    reports["observations.jsonl"] = {
        "count": obs_count,
        "status": "PASS"
        if obs_count and not obs_errors
        else ("EMPTY" if not obs_count else "FAIL"),
        "head": obs_head,
    }
    reports["derivations.jsonl"] = {
        "count": der_count,
        "status": "PASS"
        if der_count and not der_errors
        else ("EMPTY" if not der_count else "FAIL"),
        "head": der_head,
    }
    return {
        "status": "FAIL" if errors else "PASS",
        "errors": errors,
        "ledgers": reports,
        "provenance_links": {
            "observation_ids": len(observation_ids),
            "derivation_ids": len(derivation_ids),
        },
    }
