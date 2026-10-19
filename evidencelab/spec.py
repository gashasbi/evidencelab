from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from .errors import SchemaError
from . import SCHEMA_VERSION
from .outcomes import ProofState

STATUSES = {"PROVEN", "DISPROVEN", "UNKNOWN", "NOT_APPLICABLE"}
CLAIM_KINDS = {
    "node",
    "node_absence",
    "path",
    "path_absence",
    "edge",
    "relation",
    "relation_any",
    "relation_none",
    "property",
    "compare",
    "cardinality",
    "semantic",
    "same_object",
    "range_compare",
}
OPS = {"==", "!=", "<", "<=", ">=", ">", "in", "not_in", "contains", "not_contains"}


@dataclass(slots=True)
class Selector:
    type_any: list[str] = field(default_factory=list)
    type_all: list[str] = field(default_factory=list)
    canonical_type_any: list[str] = field(default_factory=list)
    canonical_type_all: list[str] = field(default_factory=list)
    name_any: list[str] = field(default_factory=list)
    name_regex: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    properties_any: dict[str, list[Any]] = field(default_factory=dict)
    properties_present: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Concept:
    id: str
    selectors: list[Selector]
    mode: str = "any"


@dataclass(slots=True)
class Slot:
    id: str
    concept: str
    required: bool = True
    max_matches: int = 200
    selector_overrides: list[Selector] = field(default_factory=list)


@dataclass(slots=True)
class Claim:
    id: str
    kind: str
    required: bool
    description: str
    source: str | None = None
    target: str | None = None
    edge_types: list[str] = field(default_factory=list)
    relation: str | None = None
    direction: str = "out"
    max_hops: int = 12
    selector: Selector | None = None
    source_selector: Selector | None = None
    target_selector: Selector | None = None
    slot: str | None = None
    equals: dict[str, Any] = field(default_factory=dict)
    any_of: dict[str, list[Any]] = field(default_factory=dict)
    left: dict[str, Any] | None = None
    right: dict[str, Any] | None = None
    operator: str | None = None
    slots: list[str] = field(default_factory=list)
    properties_present: list[str] = field(default_factory=list)
    edge_equals: dict[str, Any] = field(default_factory=dict)
    edge_any_of: dict[str, list[Any]] = field(default_factory=dict)
    allow_call_binding: bool = False
    min_count: int | None = None
    max_count: int | None = None
    proof_level: str = "PROVEN"


@dataclass(slots=True)
class Witness:
    id: str
    slots: list[str]
    claims: list[str]
    counter_claims: list[str] = field(default_factory=list)
    required: bool = True
    distinct_slots: bool = True
    max_combinations: int = 50000


@dataclass(slots=True)
class Pattern:
    pattern_id: str
    cwe: str
    name: str
    version: str
    language: str
    description: str
    schema_version: str
    concepts: dict[str, Concept]
    slots: dict[str, Slot]
    claims: list[Claim]
    counter_claims: list[Claim]
    witnesses: list[Witness]
    required_claim_groups: list[list[str]]
    metadata: dict[str, Any]
    provenance: list[dict[str, Any]]
    coverage: dict[str, Any]
    unknown_policy: str = "unknown"
    counter_unknown_policy: str = "block_match"
    source_path: str | None = None
    family_id: str | None = None
    evidence_contract: dict[str, Any] = field(default_factory=dict)
    semantic_contract: dict[str, Any] = field(default_factory=dict)
    relevance_policy: dict[str, Any] = field(default_factory=dict)
    path_budget: dict[str, Any] = field(default_factory=dict)
    provenance_policy: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Pattern":
        p = Path(path).resolve()
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise SchemaError(f"cannot read pattern {p}: {e}") from e
        obj = cls.from_dict(raw)
        obj.source_path = str(p)
        return obj

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Pattern":
        if not isinstance(raw, dict):
            raise SchemaError("pattern root must be object")
        required = (
            "schema_version",
            "pattern_id",
            "cwe",
            "name",
            "version",
            "language",
            "concepts",
            "slots",
            "claims",
        )
        for k in required:
            if k not in raw:
                raise SchemaError(f"missing required pattern field: {k}")
        schema_version = str(raw["schema_version"])
        if schema_version != SCHEMA_VERSION:
            raise SchemaError(
                f"unsupported evidence pattern schema: {schema_version}; expected {SCHEMA_VERSION}"
            )
        cwe = str(raw["cwe"]).upper()
        if not re.fullmatch(r"CWE-\d+", cwe):
            raise SchemaError("cwe must look like CWE-123")
        lang = str(raw["language"]).lower().replace(" ", "")
        if lang not in {"c/c++", "c", "c++", "cpp"}:
            raise SchemaError("EvidenceLab evaluator supports C/C++")

        concepts: dict[str, Concept] = {}
        if not isinstance(raw["concepts"], dict):
            raise SchemaError("concepts must be object")
        for cid, c in raw["concepts"].items():
            if not isinstance(c, dict) or not c.get("selectors"):
                raise SchemaError(f"concept {cid}: selectors required")
            mode = str(c.get("mode", "any")).lower()
            if mode not in {"any", "all"}:
                raise SchemaError(f"concept {cid}: invalid mode")
            concepts[str(cid)] = Concept(
                str(cid), [_selector(x) for x in c["selectors"]], mode
            )

        slots: dict[str, Slot] = {}
        for s in raw["slots"]:
            if not isinstance(s, dict):
                raise SchemaError("slot must be object")
            sid = str(s.get("id", ""))
            concept = str(s.get("concept", ""))
            if not sid or not concept or concept not in concepts:
                raise SchemaError(f"slot {sid}: invalid concept")
            if sid in slots:
                raise SchemaError(f"duplicate slot {sid}")
            mm = int(s.get("max_matches", 200))
            if mm < 1:
                raise SchemaError(f"slot {sid}: max_matches must be positive")
            slots[sid] = Slot(
                sid,
                concept,
                bool(s.get("required", True)),
                mm,
                [_selector(x) for x in s.get("selector_overrides", [])],
            )

        claims = [_claim(x) for x in raw["claims"]]
        counters = [_claim(x, counter=True) for x in raw.get("counter_evidence", [])]
        claim_ids = [c.id for c in claims + counters]
        if len(claim_ids) != len(set(claim_ids)):
            raise SchemaError(
                "claim IDs must be unique across positive and counter claims"
            )
        for c in claims + counters:
            if c.slot and c.slot not in slots:
                raise SchemaError(f"claim {c.id}: unknown slot {c.slot}")
            for ss in c.slots:
                if ss not in slots:
                    raise SchemaError(f"claim {c.id}: unknown slot {ss}")
            for ref in (c.source, c.target):
                if ref and ref not in slots:
                    raise SchemaError(f"claim {c.id}: unknown source/target slot {ref}")
        witnesses: list[Witness] = []
        all_ids = set(claim_ids)
        for w in raw.get("witnesses", []):
            if not isinstance(w, dict):
                raise SchemaError("witness must be object")
            wid = str(w.get("id", ""))
            ws = [str(x) for x in w.get("slots", [])]
            wc = [str(x) for x in w.get("claims", [])]
            wx = [str(x) for x in w.get("counter_claims", [])]
            if not wid or not ws or not wc:
                raise SchemaError(f"witness {wid}: id/slots/claims required")
            if any(s not in slots for s in ws):
                raise SchemaError(f"witness {wid}: unknown slot")
            if any(c not in all_ids for c in wc + wx):
                raise SchemaError(f"witness {wid}: unknown claim")
            mc = int(w.get("max_combinations", 50000))
            if mc < 1:
                raise SchemaError(f"witness {wid}: max_combinations must be positive")
            witnesses.append(
                Witness(
                    wid,
                    ws,
                    wc,
                    wx,
                    bool(w.get("required", True)),
                    bool(w.get("distinct_slots", True)),
                    mc,
                )
            )
        ids = [w.id for w in witnesses]
        if len(ids) != len(set(ids)):
            raise SchemaError("witness IDs must be unique")
        for group in raw.get("required_claim_groups", []):
            if not isinstance(group, list) or not group:
                raise SchemaError(
                    "required_claim_groups entries must be non-empty arrays"
                )
            if any(str(cid) not in all_ids for cid in group):
                raise SchemaError("required_claim_groups references unknown claim")

        unknown = str(raw.get("unknown_policy", "unknown")).lower()
        if unknown not in {"unknown", "non_match", "partial"}:
            raise SchemaError("unknown_policy must be unknown/non_match/partial")
        cu = str(raw.get("counter_unknown_policy", "ignore")).lower()
        if cu not in {"block_match", "ignore"}:
            raise SchemaError("counter_unknown_policy must be block_match/ignore")

        coverage = dict(raw.get("coverage", {}))
        required_dims = [str(x) for x in coverage.get("required_dimensions", [])]
        coverage["required_dimensions"] = required_dims
        provenance = list(raw.get("provenance", []))
        if not isinstance(provenance, list):
            raise SchemaError("provenance must be array")
        evidence_contract = dict(raw.get("evidence_contract", {}) or {})
        semantic_contract = dict(raw.get("semantic_contract", {}) or {})
        relevance_policy = dict(raw.get("relevance_policy", {}) or {})
        path_budget = dict(raw.get("path_budget", {}) or {})
        provenance_policy = dict(raw.get("provenance_policy", {}) or {})
        if not evidence_contract:
            raise SchemaError("current pattern requires evidence_contract")
        if not semantic_contract:
            raise SchemaError("current pattern requires semantic_contract")
        if not provenance_policy:
            raise SchemaError("current pattern requires provenance_policy")
        max_hops = int(path_budget.get("max_hops", 12) or 12)
        if max_hops < 1 or max_hops > 24:
            raise SchemaError("path_budget.max_hops must be between 1 and 24")
        for key in (
            "unknown_policy",
            "counter_unknown_policy",
            "tri_state",
            "counter_evidence_binding",
            "minimum_sufficient_witness",
        ):
            if key not in evidence_contract:
                raise SchemaError(f"current evidence_contract missing {key}")
        if (
            "canonical_graph_required" not in semantic_contract
            or "analyzer_independent" not in semantic_contract
        ):
            raise SchemaError(
                "current semantic_contract must declare canonical_graph_required and analyzer_independent"
            )
        if (
            "derived_facts_require_inputs" not in provenance_policy
            or "artifact_hashes" not in provenance_policy
        ):
            raise SchemaError(
                "current provenance_policy must declare derived_facts_require_inputs and artifact_hashes"
            )
        return cls(
            pattern_id=str(raw["pattern_id"]),
            cwe=cwe,
            name=str(raw["name"]),
            version=str(raw["version"]),
            language=str(raw["language"]),
            description=str(raw.get("description", "")),
            schema_version=schema_version,
            concepts=concepts,
            slots=slots,
            claims=claims,
            counter_claims=counters,
            witnesses=witnesses,
            required_claim_groups=[
                [str(x) for x in g] for g in raw.get("required_claim_groups", [])
            ],
            metadata=dict(raw.get("metadata", {})),
            provenance=provenance,
            coverage=coverage,
            unknown_policy=unknown,
            counter_unknown_policy=cu,
            family_id=str(raw.get("family_id"))
            if raw.get("family_id") is not None
            else None,
            evidence_contract=evidence_contract,
            semantic_contract=semantic_contract,
            relevance_policy=relevance_policy,
            path_budget=path_budget,
            provenance_policy=provenance_policy,
        )


def _selector(raw: Any) -> Selector:
    if not isinstance(raw, dict):
        raise SchemaError("selector must be object")
    return Selector(
        [str(x).upper() for x in raw.get("type_any", [])],
        [str(x).upper() for x in raw.get("type_all", [])],
        [str(x).upper() for x in raw.get("canonical_type_any", [])],
        [str(x).upper() for x in raw.get("canonical_type_all", [])],
        [str(x) for x in raw.get("name_any", [])],
        str(raw["name_regex"]) if raw.get("name_regex") is not None else None,
        dict(raw.get("properties", {})),
        {str(k): list(v) for k, v in raw.get("properties_any", {}).items()},
        [str(x) for x in raw.get("properties_present", [])],
    )


def _claim(raw: Any, counter: bool = False) -> Claim:
    if not isinstance(raw, dict):
        raise SchemaError("claim must be object")
    cid = str(raw.get("id", ""))
    kind = str(raw.get("kind", ""))
    if not cid or kind not in CLAIM_KINDS:
        raise SchemaError(f"claim {cid}: unsupported/missing kind")
    direction = str(raw.get("direction", "out")).lower()
    if direction not in {"out", "in", "either"}:
        raise SchemaError(f"claim {cid}: invalid direction")
    op = raw.get("operator")
    op = str(op) if op is not None else None
    if op and op not in OPS:
        raise SchemaError(f"claim {cid}: unsupported operator")
    rel = str(raw["relation"]).upper() if raw.get("relation") else None
    if kind == "relation" and not rel:
        raise SchemaError(f"claim {cid}: relation is required")
    if kind in {"path", "path_absence", "edge", "relation"} and (
        not raw.get("source") or not raw.get("target")
    ):
        raise SchemaError(f"claim {cid}: source/target required")
    if kind in {"relation_any", "relation_none"} and not (
        raw.get("source") or isinstance(raw.get("source_selector"), dict)
    ):
        raise SchemaError(f"claim {cid}: source slot or source_selector required")
    if kind in {"relation_any", "relation_none"} and not (
        raw.get("target") or isinstance(raw.get("target_selector"), dict)
    ):
        raise SchemaError(f"claim {cid}: target slot or target_selector required")
    if kind in {"compare", "range_compare"} and (
        not isinstance(raw.get("left"), dict)
        or not isinstance(raw.get("right"), dict)
        or op not in OPS
    ):
        raise SchemaError(f"claim {cid}: {kind} requires left/right/operator")
    if kind == "same_object" and (not raw.get("source") or not raw.get("target")):
        raise SchemaError(f"claim {cid}: same_object requires source/target")
    if kind == "semantic" and not raw.get("slot"):
        raise SchemaError(f"claim {cid}: semantic requires slot")
    if kind == "cardinality" and not raw.get("slot"):
        raise SchemaError(f"claim {cid}: cardinality requires slot")
    max_hops = int(raw.get("max_hops", 12))
    if max_hops < 1:
        raise SchemaError(f"claim {cid}: max_hops must be positive")
    edge_equals = dict(raw.get("edge_equals", {}))
    edge_any_of = {str(k): list(v) for k, v in raw.get("edge_any_of", {}).items()}
    proof = str(raw.get("proof_level", "PROVEN")).upper()
    return Claim(
        id=cid,
        kind=kind,
        required=bool(raw.get("required", not counter)),
        description=str(raw.get("description", cid)),
        source=str(raw["source"]) if raw.get("source") is not None else None,
        target=str(raw["target"]) if raw.get("target") is not None else None,
        edge_types=[str(x).upper() for x in raw.get("edge_types", [])],
        relation=rel,
        direction=direction,
        max_hops=max_hops,
        selector=_selector(raw["selector"])
        if isinstance(raw.get("selector"), dict)
        else None,
        source_selector=_selector(raw["source_selector"])
        if isinstance(raw.get("source_selector"), dict)
        else None,
        target_selector=_selector(raw["target_selector"])
        if isinstance(raw.get("target_selector"), dict)
        else None,
        slot=str(raw["slot"]) if raw.get("slot") is not None else None,
        equals=dict(raw.get("equals", {})),
        any_of={str(k): list(v) for k, v in raw.get("any_of", {}).items()},
        left=dict(raw["left"]) if isinstance(raw.get("left"), dict) else None,
        right=dict(raw["right"]) if isinstance(raw.get("right"), dict) else None,
        operator=op,
        slots=[str(x) for x in raw.get("slots", [])],
        properties_present=[str(x) for x in raw.get("properties_present", [])],
        edge_equals=edge_equals,
        edge_any_of=edge_any_of,
        allow_call_binding=bool(raw.get("allow_call_binding", False)),
        min_count=int(raw["min_count"]) if raw.get("min_count") is not None else None,
        max_count=int(raw["max_count"]) if raw.get("max_count") is not None else None,
        proof_level=proof,
    )
