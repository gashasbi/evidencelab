from __future__ import annotations
from pathlib import Path
from typing import Any
import json


class TEFError(ValueError):
    pass


def load_document(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".json"}:
        raw = json.loads(text)
    elif p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise TEFError(
                "YAML support requires PyYAML; install with pip install evidencelab[tef]"
            ) from exc
        raw = yaml.safe_load(text)
    else:
        raise TEFError("TEF input must be JSON or YAML")
    if not isinstance(raw, dict):
        raise TEFError("TEF root must be an object")
    return raw


def validate_tef(raw: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    defect = raw.get("defect")
    evidence = raw.get("evidence")
    if not isinstance(defect, dict):
        errors.append("defect block is required")
    else:
        for key in ("product", "vendor", "type", "cwe", "versions", "presence"):
            if key not in defect:
                errors.append(f"defect.{key} is required")
        if not isinstance(defect.get("versions"), list):
            errors.append("defect.versions must be an array")
        presence = defect.get("presence")
        allowed = {
            "static_artefact",
            "static_config",
            "behavioural_deterministic",
            "behavioural_stateful",
            "behavioural_timing",
            "probabilistic",
            "environmental",
            "design_flaw",
            "supply_chain",
        }
        if presence is not None and presence not in allowed:
            errors.append(f"unsupported defect.presence: {presence}")
    if not isinstance(evidence, list) or not evidence:
        errors.append("evidence must be a non-empty array")
    else:
        for i, scenario in enumerate(evidence):
            if not isinstance(scenario, dict):
                errors.append(f"evidence[{i}] must be an object")
                continue
            for key in ("title", "given", "when", "then"):
                if key not in scenario:
                    errors.append(f"evidence[{i}].{key} is required")
                elif key == "title":
                    if not isinstance(scenario[key], str) or not scenario[key].strip():
                        errors.append(f"evidence[{i}].title must be a non-empty string")
                elif not isinstance(scenario[key], list) or not all(
                    isinstance(x, str) for x in scenario[key]
                ):
                    errors.append(f"evidence[{i}].{key} must be an array of strings")
    return errors


def to_evidencelab_notes(raw: dict[str, Any]) -> dict[str, Any]:
    errors = validate_tef(raw)
    if errors:
        raise TEFError("invalid TEF: " + "; ".join(errors))
    defect = raw["defect"]
    scenarios = []
    for s in raw["evidence"]:
        scenarios.append(
            {
                "title": s["title"],
                "preconditions": s["given"],
                "trigger": s["when"],
                "observed_outcome": s["then"],
                "location": s.get("location"),
                "reproduction": s.get("reproduction"),
            }
        )
    return {
        "format": "evidencelab-tef-bridge",
        "tef_status": "input-draft",
        "defect": defect,
        "scenarios": scenarios,
        "notes": "TEF is treated as an intake/triage layer, not as the internal graph-evidence proof standard.",
    }
