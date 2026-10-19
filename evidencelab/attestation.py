from __future__ import annotations

from typing import Any


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)


def is_trusted_attestation(attestation: Any) -> bool:
    if not isinstance(attestation, dict):
        return False

    level = str(attestation.get("level", "")).upper()

    if level != "ANALYZER_ATTESTED":
        return False

    verified_inputs = attestation.get("verified_merge_input_sha256")

    return (
        attestation.get("integrity_validation") == "MERGE_INPUTS_VERIFIED"
        and str(attestation.get("capture_status", "")).upper() == "PASS"
        and bool(str(attestation.get("analyzer", "")).strip())
        and _is_sha256(attestation.get("source_sha256"))
        and _is_sha256(attestation.get("capture_manifest_sha256"))
        and isinstance(verified_inputs, dict)
        and _is_sha256(verified_inputs.get("graphml"))
        and all(_is_sha256(value) for value in verified_inputs.values())
    )
