from __future__ import annotations

"""EvidenceLab Specification Language (ELS) v1.

ELS is deliberately small and declarative. It describes evidence semantics only:
concepts, slots, claims, witnesses, counter-evidence and policies. It is not a
general-purpose graph language, analyzer language, dataset DSL, or automation
language.
"""

from dataclasses import dataclass, field
import ast
import json
import re
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION
from .errors import EvidenceLabError
from .spec import Pattern


class ELSParseError(EvidenceLabError):
    pass


@dataclass
class Block:
    kind: str
    name: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list["Block"] = field(default_factory=list)
    line: int = 0


_TOP_KEYS = {
    "cwe",
    "name",
    "version",
    "language",
    "family_id",
    "description",
    "unknown_policy",
    "counter_unknown_policy",
    "path_budget",
    "coverage",
    "metadata",
    "provenance",
    "provenance_policy",
    "relevance_policy",
    "evidence_contract",
    "semantic_contract",
    "required_claim_group",
}

_BOOL = {"true": True, "false": False}


def _strip_comment(line: str) -> str:
    in_quote = False
    quote = ""
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
            continue
        if ch in {'"', "'"}:
            if not in_quote:
                in_quote, quote = True, ch
            elif quote == ch:
                in_quote = False
        if ch == "#" and not in_quote:
            return line[:i]
    return line


def _parse_value(text: str) -> Any:
    text = text.strip()
    if not text:
        return ""
    if text in _BOOL:
        return _BOOL[text]
    if text.lower() in {"null", "none"}:
        return None
    if text[0:1] in {'"', "'"} and text[-1:] == text[0]:
        try:
            return ast.literal_eval(text)
        except Exception:
            return text[1:-1]
    if text[0:1] in "[{" and text[-1:] in "]}":
        try:
            return json.loads(text)
        except Exception:
            try:
                return ast.literal_eval(text)
            except Exception as exc:
                raise ELSParseError(f"invalid structured value: {text}") from exc
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", text):
        return float(text)

    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        out: dict[str, Any] = {}
        if inner:
            for piece in re.split(r",\s*", inner):
                if "=" not in piece:
                    raise ELSParseError(f"invalid object member: {piece}")
                k, v = piece.split("=", 1)
                out[k.strip()] = _parse_value(v)
        return out
    return text


def _tokenize_header(line: str) -> list[str]:
    import shlex

    try:
        return shlex.split(line, posix=True)
    except ValueError as exc:
        raise ELSParseError(f"invalid header: {line}") from exc


def parse_els(text: str) -> Block:
    root = Block("root", line=0)
    stack: list[Block] = [root]
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue

        if line == "}":
            if len(stack) == 1:
                raise ELSParseError(f"line {lineno}: unexpected }}")
            stack.pop()
            continue

        inline = re.match(r"^(\S+)\s+(\{.*\}|\[.*\])$", line)
        if inline:
            stack[-1].attrs[inline.group(1)] = _parse_value(inline.group(2))
            continue
        opens = line.endswith("{")
        if opens:
            line = line[:-1].strip()
        if opens:
            toks = _tokenize_header(line)
            if not toks:
                raise ELSParseError(f"line {lineno}: empty block")
            kind = toks[0]
            name = toks[1] if len(toks) >= 2 else None
            block = Block(kind, name, line=lineno)
            stack[-1].children.append(block)
            stack.append(block)
            continue
        toks = _tokenize_header(line)
        if not toks:
            continue
        key = toks[0]
        rest = line[len(key) :].strip()
        if key == "required_claim_group":
            stack[-1].attrs.setdefault("required_claim_group", []).append(
                _parse_value(rest)
            )
            continue
        if not rest:
            raise ELSParseError(f"line {lineno}: `{key}` needs a value")
        stack[-1].attrs[key] = _parse_value(rest)
    if len(stack) != 1:
        raise ELSParseError(
            f"unclosed block `{stack[-1].kind}` at line {stack[-1].line}"
        )
    if len(root.children) != 1 or root.children[0].kind != "evidence":
        raise ELSParseError("ELS document must contain exactly one `evidence` block")
    return root


def _ensure_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _selector_from_block(block: Block) -> dict[str, Any]:
    data = dict(block.attrs)
    for child in block.children:
        if child.kind in {"selector", "select"}:
            data.update(child.attrs)
        else:
            raise ELSParseError(
                f"line {child.line}: unsupported selector child `{child.kind}`"
            )
    allowed = {
        "type_any",
        "type_all",
        "canonical_type_any",
        "canonical_type_all",
        "name_any",
        "name_regex",
        "properties",
        "properties_any",
        "properties_present",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ELSParseError(f"unsupported selector keys: {sorted(unknown)}")
    return {k: v for k, v in data.items() if k in allowed}


def _claim_dict(block: Block, *, counter: bool = False) -> dict[str, Any]:
    data = dict(block.attrs)
    for child in block.children:
        if child.kind == "selector":
            data["selector"] = _selector_from_block(child)
        elif child.kind == "source_selector":
            data["source_selector"] = _selector_from_block(child)
        elif child.kind == "target_selector":
            data["target_selector"] = _selector_from_block(child)
        elif child.kind in {"left", "right"}:
            data[child.kind] = dict(child.attrs)
        else:
            raise ELSParseError(
                f"line {child.line}: unsupported claim child `{child.kind}`"
            )
    if counter:
        data["required"] = bool(data.get("required", False))
    else:
        data["required"] = bool(data.get("required", True))
    data.setdefault("description", block.name or block.attrs.get("id", "claim"))
    if not block.name:
        raise ELSParseError(f"line {block.line}: claim/counter requires an id")
    data["id"] = block.name
    return data


def compile_els(text: str, source: str | None = None) -> dict[str, Any]:
    root = parse_els(text)
    ev = root.children[0]
    if not ev.name:
        raise ELSParseError(f"line {ev.line}: evidence requires an id")
    attrs = dict(ev.attrs)
    for k in attrs:
        if k not in _TOP_KEYS:
            if not k.startswith("meta_"):
                raise ELSParseError(f"line {ev.line}: unsupported top-level key `{k}`")

    concepts: dict[str, Any] = {}
    slots: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    counters: list[dict[str, Any]] = []
    witnesses: list[dict[str, Any]] = []
    provenance = (
        attrs.get("provenance", []) if isinstance(attrs.get("provenance"), list) else []
    )
    metadata = (
        attrs.get("metadata", {}) if isinstance(attrs.get("metadata"), dict) else {}
    )
    for child in ev.children:
        if child.kind == "concept":
            if not child.name:
                raise ELSParseError(f"line {child.line}: concept requires an id")
            selectors = [
                _selector_from_block(c)
                for c in child.children
                if c.kind in {"selector", "select"}
            ]
            if not selectors:
                raise ELSParseError(
                    f"line {child.line}: concept requires at least one selector"
                )
            concepts[child.name] = {
                "selectors": selectors,
                "mode": str(child.attrs.get("mode", "any")),
            }
        elif child.kind == "slot":
            if not child.name:
                raise ELSParseError(f"line {child.line}: slot requires an id")
            slots.append(
                {
                    "id": child.name,
                    "concept": child.attrs.get("concept", ""),
                    "required": bool(child.attrs.get("required", True)),
                    "max_matches": int(child.attrs.get("max_matches", 200)),
                }
            )
            for c in child.children:
                if c.kind == "selector_override":
                    slots[-1].setdefault("selector_overrides", []).append(
                        _selector_from_block(c)
                    )
                else:
                    raise ELSParseError(
                        f"line {c.line}: unsupported slot child `{c.kind}`"
                    )
        elif child.kind == "claim":
            claims.append(_claim_dict(child))
        elif child.kind == "counter":
            counters.append(_claim_dict(child, counter=True))
        elif child.kind == "witness":
            if not child.name:
                raise ELSParseError(f"line {child.line}: witness requires an id")
            w = {
                "id": child.name,
                "slots": [str(x) for x in _ensure_list(child.attrs.get("slots"))],
                "claims": [str(x) for x in _ensure_list(child.attrs.get("claims"))],
                "counter_claims": [
                    str(x) for x in _ensure_list(child.attrs.get("counter_claims"))
                ],
                "required": bool(child.attrs.get("required", True)),
                "distinct_slots": bool(child.attrs.get("distinct_slots", True)),
                "max_combinations": int(child.attrs.get("max_combinations", 50000)),
            }
            witnesses.append(w)
        elif child.kind in {"selector", "left", "right", "counter_policy"}:
            raise ELSParseError(
                f"line {child.line}: `{child.kind}` is only valid inside a declaration block"
            )
        else:
            raise ELSParseError(
                f"line {child.line}: unsupported evidence child `{child.kind}`"
            )

    if not concepts:
        raise ELSParseError("evidence must define at least one concept")
    if not slots:
        raise ELSParseError("evidence must define at least one slot")
    if not claims:
        raise ELSParseError("evidence must define at least one positive claim")
    if not witnesses:
        raise ELSParseError("evidence must define at least one witness")

    pattern = {
        "schema_version": SCHEMA_VERSION,
        "pattern_id": ev.name,
        "cwe": str(attrs.get("cwe", "")).upper(),
        "name": str(attrs.get("name", ev.name)),
        "version": str(attrs.get("version", "1.0.0")),
        "language": str(attrs.get("language", "C/C++")),
        "description": str(attrs.get("description", "")),
        "family_id": str(attrs.get("family_id", ev.name)),
        "unknown_policy": str(attrs.get("unknown_policy", "unknown")).lower(),
        "counter_unknown_policy": str(
            attrs.get("counter_unknown_policy", "block_match")
        ).lower(),
        "concepts": concepts,
        "slots": slots,
        "claims": claims,
        "counter_evidence": counters,
        "witnesses": witnesses,
        "required_claim_groups": attrs.get("required_claim_group", []),
        "metadata": {
            **metadata,
            "source_language": "ELS",
            "els_version": "1.0",
            "source": source,
        },
        "provenance": provenance,
        "coverage": attrs.get("coverage", {})
        if isinstance(attrs.get("coverage"), dict)
        else {},
        "evidence_contract": attrs.get("evidence_contract", {})
        if isinstance(attrs.get("evidence_contract"), dict)
        else {},
        "semantic_contract": attrs.get("semantic_contract", {})
        if isinstance(attrs.get("semantic_contract"), dict)
        else {},
        "relevance_policy": attrs.get("relevance_policy", {})
        if isinstance(attrs.get("relevance_policy"), dict)
        else {},
        "path_budget": attrs.get("path_budget", {})
        if isinstance(attrs.get("path_budget"), dict)
        else {},
        "provenance_policy": attrs.get("provenance_policy", {})
        if isinstance(attrs.get("provenance_policy"), dict)
        else {},
    }

    pattern["evidence_contract"] = {
        "unknown_policy": pattern["unknown_policy"],
        "counter_unknown_policy": pattern["counter_unknown_policy"],
        "tri_state": True,
        "counter_evidence_binding": "same_witness",
        "minimum_sufficient_witness": True,
        **pattern["evidence_contract"],
    }
    pattern["semantic_contract"] = {
        "canonical_graph_required": True,
        "analyzer_independent": True,
        **pattern["semantic_contract"],
    }
    pattern["provenance_policy"] = {
        "derived_facts_require_inputs": True,
        "artifact_hashes": True,
        "require_query_hash": False,
        **pattern["provenance_policy"],
    }
    pattern["path_budget"] = {
        "max_hops": 12,
        "max_paths_per_claim": 100,
        **pattern["path_budget"],
    }

    Pattern.from_dict(pattern)
    return pattern


def validate_els(path: str | Path) -> dict[str, Any]:
    p = Path(path).resolve()
    try:
        raw = p.read_text(encoding="utf-8")
        compiled = compile_els(raw, str(p))
        return {
            "status": "PASS",
            "source": str(p),
            "pattern_id": compiled["pattern_id"],
            "schema_version": compiled["schema_version"],
            "errors": [],
        }
    except Exception as exc:
        return {
            "status": "FAIL",
            "source": str(p),
            "pattern_id": None,
            "schema_version": SCHEMA_VERSION,
            "errors": [str(exc)],
        }


def compile_els_file(path: str | Path) -> dict[str, Any]:
    p = Path(path).resolve()
    compiled = compile_els(p.read_text(encoding="utf-8"), str(p))
    return compiled


def write_compiled(path: str | Path, out: str | Path) -> dict[str, Any]:
    compiled = compile_els_file(path)
    dst = Path(out).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        json.dumps(compiled, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS",
        "source": str(Path(path).resolve()),
        "out": str(dst),
        "pattern_id": compiled["pattern_id"],
        "schema_version": compiled["schema_version"],
    }
