from __future__ import annotations
from pathlib import Path
from typing import Any
import hashlib, json, re


def apply_recipe(text: str, recipe: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(recipe.get("kind", "replace_literal"))
    if kind == "replace_literal":
        old = str(recipe["old"])
        new = str(recipe["new"])
        count = text.count(old)
        if count < 1:
            raise ValueError(f"replace_literal old text not found: {old}")
        if not recipe.get("replace_all", False) and count != 1:
            raise ValueError(
                "replace_literal matched multiple locations; use replace_all explicitly"
            )
        return text.replace(old, new, -1 if recipe.get("replace_all", False) else 1), {
            "kind": kind,
            "old": old,
            "new": new,
            "matches": count,
        }
    if kind == "regex_replace":
        pat = str(recipe["pattern"])
        repl = str(recipe["replacement"])
        count = len(re.findall(pat, text, flags=re.M))
        if count < 1:
            raise ValueError(f"regex did not match: {pat}")
        return re.sub(
            pat,
            repl,
            text,
            count=0 if recipe.get("replace_all", False) else 1,
            flags=re.M,
        ), {"kind": kind, "pattern": pat, "replacement": repl, "matches": count}
    if kind == "insert_after":
        anchor = str(recipe["anchor"])
        pos = text.find(anchor)
        if pos < 0:
            raise ValueError(f"anchor not found: {anchor}")
        at = pos + len(anchor)
        return text[:at] + str(recipe["text"]) + text[at:], {
            "kind": kind,
            "anchor": anchor,
        }
    raise ValueError(f"unknown mutation recipe: {kind}")


def mutate_file(
    source: str | Path, recipes: list[dict[str, Any]], out_dir: str | Path
) -> dict[str, Any]:
    src = Path(source).resolve()
    text = src.read_text(encoding="utf-8")
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cases = []
    for i, recipe in enumerate(recipes, 1):
        mutated, change = apply_recipe(text, recipe)
        key = hashlib.sha256(
            (str(src) + json.dumps(recipe, sort_keys=True)).encode()
        ).hexdigest()[:16]
        dst = out / f"{key}-{src.name}"
        dst.write_text(mutated, encoding="utf-8")
        cases.append(
            {
                "id": f"mutation-{key}",
                "source": str(dst),
                "mutation_of": src.name,
                "changed_dimension": recipe.get("dimension") or change["kind"],
                "change": change,
            }
        )
    return {
        "status": "PASS",
        "source": str(src),
        "case_count": len(cases),
        "cases": cases,
    }
