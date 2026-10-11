from __future__ import annotations
from . import SCHEMA_VERSION

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable

from .outcomes import ProofState, combine_states, normalize_proof_state
from .provenance import sha256_json


class EvidenceKind(str, Enum):
    OBSERVATION = "OBSERVATION"
    DERIVATION = "DERIVATION"
    FACT = "FACT"
    RELATION = "RELATION"
    LOCATION = "LOCATION"
    COUNTER = "COUNTER"
    ASSUMPTION = "ASSUMPTION"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    source_type: str
    source_id: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceItem:
    id: str
    kind: str
    state: str
    statement: str
    value: Any = None
    subject: str | None = None
    predicate: str | None = None
    provenance: list[EvidenceRef | dict[str, Any]] = field(default_factory=list)
    confidence: float | None = None
    assumptions: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["state"] = normalize_proof_state(self.state)
        out["provenance"] = [
            x.to_dict() if isinstance(x, EvidenceRef) else dict(x)
            for x in self.provenance
        ]
        return out


class EvidenceLedger:
    """Typed ledger for raw observations, derivations, facts and evidence.

    The Evidence contract enforces the central trust boundary: a DERIVATION/FACT/EVIDENCE item that claims a
    definitive state must cite at least one prior artifact/fact. Raw observations cite the
    analyzer artifact they came from. UNKNOWN and PARTIAL are first-class states.
    """

    def __init__(self, items: Iterable[EvidenceItem] | None = None) -> None:
        self.items: dict[str, EvidenceItem] = {}
        for item in items or []:
            self.add(item)

    def add(self, item: EvidenceItem) -> EvidenceItem:
        if not item.id or not item.statement:
            raise ValueError("evidence item id and statement are required")
        item.state = normalize_proof_state(item.state)
        if item.confidence is not None and not 0.0 <= float(item.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if item.kind in {
            EvidenceKind.DERIVATION.value,
            EvidenceKind.FACT.value,
            EvidenceKind.COUNTER.value,
        }:
            if item.state in {
                ProofState.PROVEN.value,
                ProofState.DISPROVEN.value,
            } and not (item.provenance or item.inputs):
                raise ValueError(
                    f"definitive {item.kind} requires provenance or inputs: {item.id}"
                )
        self.items[item.id] = item
        return item

    def extend(self, items: Iterable[EvidenceItem]) -> None:
        for item in items:
            self.add(item)

    def by_state(self, state: ProofState | str) -> list[EvidenceItem]:
        target = normalize_proof_state(state)
        return [
            x for x in self.items.values() if normalize_proof_state(x.state) == target
        ]

    def by_kind(self, kind: str) -> list[EvidenceItem]:
        return [x for x in self.items.values() if x.kind == kind]

    def by_tag(self, tag: str) -> list[EvidenceItem]:
        return [x for x in self.items.values() if tag in x.tags]

    def validate(self) -> dict[str, Any]:
        errors: list[str] = []
        known = set(self.items)
        for item in self.items.values():
            if item.kind in {
                EvidenceKind.DERIVATION.value,
                EvidenceKind.FACT.value,
                EvidenceKind.COUNTER.value,
            } and item.state in {"PROVEN", "DISPROVEN"}:
                refs = set(item.inputs)
                refs |= {
                    str(p.source_id)
                    for p in item.provenance
                    if isinstance(p, EvidenceRef)
                    or isinstance(p, dict)
                    and p.get("source_id")
                }
                if not refs:
                    errors.append(
                        f"{item.id}: definitive derived evidence has no provenance"
                    )
                missing_internal = [
                    x
                    for x in item.inputs
                    if x not in known
                    and not str(x).startswith(
                        ("graph:", "query:", "artifact:", "dataset:", "literature:")
                    )
                ]
                if missing_internal:
                    errors.append(
                        f"{item.id}: missing ledger inputs: {', '.join(missing_internal)}"
                    )
        return {
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
            "item_count": len(self.items),
        }

    def digest(self) -> str:
        return sha256_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "digest": sha256_json([x.to_dict() for x in self.items.values()]),
            "items": [x.to_dict() for x in self.items.values()],
        }


def combine_evidence_states(states: Iterable[str], require_all: bool = True) -> str:
    return combine_states(states, require_all=require_all)
