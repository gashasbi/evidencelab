from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION, __version__
from .canonical import canonical_node_type
from .provenance import sha256_file
from .spec import Pattern


def migrate_pattern_to_current(
    source: str | Path, out: str | Path, *, family_id: str | None = None
) -> dict[str, Any]:
    """Normalize a serialized Evidence Pattern to the single public artifact contract.

    This operation changes representation and adds required execution-contract defaults only.
    It does not invent vulnerability semantics, labels, evidence, provenance inputs or research
    validity. Every imported result is marked for explicit researcher review.
    """
    src = Path(source).resolve()
    try:
        raw = json.loads(src.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"cannot read Evidence Pattern: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Evidence Pattern root must be an object")
    for field in (
        "pattern_id",
        "cwe",
        "name",
        "language",
        "concepts",
        "slots",
        "claims",
    ):
        if field not in raw:
            raise ValueError(
                f"cannot import Evidence Pattern: required field {field!r} is missing"
            )

    source_schema = str(raw.get("schema_version", "unspecified"))
    raw = dict(raw)
    raw["schema_version"] = SCHEMA_VERSION
    raw["version"] = __version__
    fid = family_id or str(
        raw.get("family_id") or f"{str(raw['cwe']).lower()}-{raw['pattern_id']}"
    )
    raw["family_id"] = fid

    def normalize_selector(selector: dict[str, Any]) -> dict[str, Any]:
        result = dict(selector)
        for source_key, target_key in (
            ("type_any", "canonical_type_any"),
            ("type_all", "canonical_type_all"),
        ):
            values = list(result.get(source_key, []) or [])
            if values and not result.get(target_key):
                result[target_key] = sorted(
                    {canonical_node_type(str(value)) for value in values}
                )
        return result

    concepts = raw.get("concepts") or {}
    if not isinstance(concepts, dict) or not concepts:
        raise ValueError(
            "cannot import Evidence Pattern: concepts must be a non-empty object"
        )
    for concept in concepts.values():
        if isinstance(concept, dict):
            concept["selectors"] = [
                normalize_selector(x)
                for x in concept.get("selectors", [])
                if isinstance(x, dict)
            ]
    for slot in raw.get("slots", []) or []:
        if isinstance(slot, dict):
            slot["selector_overrides"] = [
                normalize_selector(x)
                for x in slot.get("selector_overrides", [])
                if isinstance(x, dict)
            ]

    metadata = dict(raw.get("metadata") or {})
    for key in (
        "source_schema_version",
        "migration_status",
        "research_claim_policy_version",
    ):
        metadata.pop(key, None)
    metadata["evidence_definition_version"] = SCHEMA_VERSION
    metadata["migration_status"] = "MIGRATED_REQUIRES_REVIEW"
    raw["metadata"] = metadata

    provenance = [
        item
        for item in (raw.get("provenance") or [])
        if not (
            isinstance(item, dict) and str(item.get("kind", "")).lower() == "migration"
        )
    ]
    provenance.append(
        {
            "kind": "migration",
            "tool": "EvidenceLab",
            "tool_version": __version__,
            "source_schema_version": source_schema,
            "target_schema_version": SCHEMA_VERSION,
            "source_pattern_sha256": sha256_file(src),
            "note": "Serialized representation normalized to the current contract; semantic validity requires researcher review and fresh evaluation.",
        }
    )
    raw["provenance"] = provenance

    unknown = str(raw.get("unknown_policy", "unknown"))
    counter_unknown = str(raw.get("counter_unknown_policy", "block_match"))
    evidence_contract = dict(raw.get("evidence_contract") or {})
    evidence_contract.update(
        {
            "unknown_policy": unknown,
            "counter_unknown_policy": counter_unknown,
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
        }
    )
    raw["evidence_contract"] = evidence_contract

    semantic_contract = dict(raw.get("semantic_contract") or {})
    semantic_contract.update(
        {"canonical_graph_required": True, "analyzer_independent": True}
    )
    semantic_contract.setdefault(
        "required_analysis_dimensions",
        list((raw.get("coverage") or {}).get("required_dimensions", [])),
    )
    raw["semantic_contract"] = semantic_contract

    relevance_policy = dict(raw.get("relevance_policy") or {})
    relevance_policy.setdefault("minimum_sufficient_witness", True)
    relevance_policy.setdefault("max_path_hops", 12)
    relevance_policy.setdefault("reject_unrelated_bindings", True)
    raw["relevance_policy"] = relevance_policy

    path_budget = dict(raw.get("path_budget") or {})
    try:
        hops = int(path_budget.get("max_hops", 12) or 12)
    except (TypeError, ValueError):
        hops = 12
    path_budget["max_hops"] = min(max(hops, 1), 24)
    path_budget.setdefault("max_paths_per_claim", 100)
    raw["path_budget"] = path_budget

    provenance_policy = dict(raw.get("provenance_policy") or {})
    provenance_policy.update(
        {"derived_facts_require_inputs": True, "artifact_hashes": True}
    )
    provenance_policy.setdefault("literature_linkage", True)
    provenance_policy.setdefault("require_query_hash", True)
    provenance_policy.setdefault("case_identity_required", True)
    raw["provenance_policy"] = provenance_policy

    # Validate the normalized payload before creating output, so failures cannot leave a partial file.
    Pattern.from_dict(raw)
    dst = Path(out).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS",
        "source": str(src),
        "out": str(dst),
        "family_id": fid,
        "source_schema_version": source_schema,
        "schema_version": SCHEMA_VERSION,
        "migration_status": "MIGRATED_REQUIRES_REVIEW",
    }
