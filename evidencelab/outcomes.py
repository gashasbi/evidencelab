from __future__ import annotations

from enum import Enum
from typing import Iterable


class ProofState(str, Enum):
    PROVEN = "PROVEN"
    DISPROVEN = "DISPROVEN"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvaluationOutcome(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


_RANK = {
    ProofState.NOT_APPLICABLE.value: 0,
    ProofState.PROVEN.value: 3,
    ProofState.DISPROVEN.value: 3,
    ProofState.PARTIAL.value: 2,
    ProofState.UNKNOWN.value: 1,
}


def normalize_proof_state(
    value: str | ProofState | None, *, default: str = "UNKNOWN"
) -> str:
    if isinstance(value, ProofState):
        return value.value
    v = str(value or default).upper().replace("-", "_")
    aliases = {
        "OBSERVED": "PROVEN",
        "TRUE": "PROVEN",
        "FALSE": "DISPROVEN",
        "NO_MATCH": "DISPROVEN",
        "N_A": "NOT_APPLICABLE",
        "NA": "NOT_APPLICABLE",
        "INCOMPLETE": "PARTIAL",
    }
    v = aliases.get(v, v)
    return v if v in {x.value for x in ProofState} else default


def normalize_outcome(
    value: str | EvaluationOutcome | None, *, default: str = "UNKNOWN"
) -> str:
    if isinstance(value, EvaluationOutcome):
        return value.value
    v = str(value or default).upper()
    aliases = {"DISPROVEN": "NO_MATCH", "FALSE": "NO_MATCH", "TRUE": "MATCH"}
    v = aliases.get(v, v)
    return v if v in {x.value for x in EvaluationOutcome} else default


def combine_states(states: Iterable[str], require_all: bool = True) -> str:
    vals = [normalize_proof_state(s) for s in states]
    if not vals:
        return ProofState.NOT_APPLICABLE.value
    if any(v == ProofState.DISPROVEN.value for v in vals):
        return ProofState.DISPROVEN.value
    if any(v == ProofState.UNKNOWN.value for v in vals):
        return ProofState.UNKNOWN.value
    if any(v == ProofState.PARTIAL.value for v in vals):
        return ProofState.PARTIAL.value
    if all(v == ProofState.PROVEN.value for v in vals):
        return ProofState.PROVEN.value
    if require_all:
        return ProofState.PARTIAL.value
    return max(vals, key=lambda v: _RANK.get(v, 0))


def aggregate_outcomes(outcomes: Iterable[str]) -> str:
    vals = [normalize_outcome(x) for x in outcomes]
    if not vals:
        return EvaluationOutcome.UNKNOWN.value
    if EvaluationOutcome.MATCH.value in vals:
        return EvaluationOutcome.MATCH.value
    if EvaluationOutcome.PARTIAL.value in vals:
        return EvaluationOutcome.PARTIAL.value
    if EvaluationOutcome.UNKNOWN.value in vals:
        return EvaluationOutcome.UNKNOWN.value
    return EvaluationOutcome.NO_MATCH.value
