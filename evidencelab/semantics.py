from __future__ import annotations
import ast
import operator
import re
from typing import Any
from .models import Graph, Node

_ARRAY_RE = re.compile(r"^(?P<base>.+?)\s*\[(?P<len>\d+)\]\s*$")
_C_ARRAY_CODE_RE = re.compile(
    r"\b(?:char|short|int|long|float|double|unsigned|signed|bool|struct\s+\w+|\w+)\s+\w+\s*\[(?P<len>\d+)\]"
)
_INT_RE = re.compile(r"^[+-]?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|\d+)$")

SEMANTIC_EDGE_ALIASES: dict[str, set[str]] = {
    "DATA_FLOW": {"DATA_FLOW", "REACHING_DEF"},
    "ARGUMENT": {"ARGUMENT"},
    "REFERENCE": {"REF"},
    "CALL": {"CALL"},
    "AST": {"AST"},
    "CONTAINS": {"CONTAINS"},
    "CFG": {"CFG"},
    "DOMINANCE": {"DOMINATE", "POST_DOMINATE"},
    "CONTROL_DEPENDENCY": {"CONTROL_DEPENDENCY", "CONTROLS"},
    "CALL_ARGUMENT": {"ARGUMENT"},
    "SAME_OBJECT": {"REF", "SAME_OBJECT"},
    "PARENT_METHOD": set(),
}


_NUMERIC_CALLS = {
    "<operator>.addition": operator.add,
    "<operator>.subtraction": operator.sub,
    "<operator>.multiplication": operator.mul,
    "<operator>.division": operator.truediv,
    "<operator>.modulo": operator.mod,
    "<operator>.shiftLeft": operator.lshift,
    "<operator>.shiftRight": operator.rshift,
    "<operator>.and": operator.and_,
    "<operator>.or": operator.or_,
    "<operator>.xor": operator.xor,
    "<operator>.minus": operator.neg,
    "<operator>.plus": operator.pos,
}


def _num(v: Any) -> int | float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    if _INT_RE.fullmatch(s):
        try:
            return int(s, 0)
        except ValueError:
            try:
                return int(s)
            except ValueError:
                return None
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", s):
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _string_length(code: str) -> int | None:
    s = code.strip()
    if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
        return None
    try:
        val = ast.literal_eval(s)
        return len(val) if isinstance(val, str) else None
    except Exception:
        return None


def _array_info(node: Node) -> dict[str, Any]:
    raw_type = str(
        node.get("typeFullName", node.get("TYPE_FULL_NAME", "")) or ""
    ).strip()
    raw_code = str(node.get("code", node.get("CODE", "")) or "").strip()
    for raw, source in ((raw_type, "typeFullName"), (raw_code, "code")):
        m = _ARRAY_RE.fullmatch(raw)
        if m:
            base = m.group("base").strip()
            length = int(m.group("len"))
            char_like = base in {"char", "signed char", "unsigned char", "char8_t"}
            return {
                "is_array": True,
                "element_type": base,
                "length": length,
                "element_count": length,
                "source": source,
                "length_proof": "DIRECT_LITERAL",
                "capacity_unit": "BYTES" if char_like else "ELEMENTS",
                "byte_capacity_known": char_like,
            }
    m = _C_ARRAY_CODE_RE.search(raw_code)
    if m:
        length = int(m.group("len"))

        prefix = raw_code[: m.start("len")].strip()
        char_like = bool(
            re.search(r"\b(?:signed\s+char|unsigned\s+char|char|char8_t)\b", prefix)
        )
        return {
            "is_array": True,
            "length": length,
            "element_count": length,
            "source": "code",
            "length_proof": "DIRECT_LITERAL",
            "capacity_unit": "BYTES" if char_like else "ELEMENTS",
            "byte_capacity_known": char_like,
        }
    return {"is_array": False, "length_proof": "UNKNOWN", "byte_capacity_known": False}


def _derive_storage(node: Node) -> dict[str, Any]:
    code = str(node.get("code", "") or "")
    if node.type == "LOCAL":
        if code.lstrip().startswith("<global>"):
            return {
                "storage_duration": "STATIC_GLOBAL",
                "stack_candidate": False,
                "physical_stack_region": "UNKNOWN",
                "storage_proof": "CPG_GLOBAL_PLACEHOLDER",
            }
        if re.search(r"\bstatic\b", code):
            return {
                "storage_duration": "STATIC_LOCAL",
                "stack_candidate": False,
                "physical_stack_region": "UNKNOWN",
                "storage_proof": "LEXICAL_LOCAL_STATIC",
            }
        return {
            "storage_duration": "AUTOMATIC",
            "stack_candidate": True,
            "physical_stack_region": "UNKNOWN",
            "storage_proof": "CPG_LOCAL_AUTOMATIC_SEMANTICS",
        }
    if node.type.startswith("METHOD_PARAMETER"):
        return {
            "storage_duration": "PARAMETER",
            "stack_candidate": False,
            "physical_stack_region": "UNKNOWN",
        }
    return {}


def _parent_lookup(g: Graph) -> tuple[dict[str, str], dict[str, str]]:
    parent_method: dict[str, str] = {}
    parent_file: dict[str, str] = {}
    structural = {"AST", "CONTAINS", "SOURCE_FILE"}
    rev: dict[str, list[str]] = {nid: [] for nid in g.nodes}
    for e in g.edges:
        if e.type in structural and e.source in g.nodes and e.target in g.nodes:
            rev[e.target].append(e.source)
    from functools import lru_cache

    @lru_cache(maxsize=None)
    def nearest(nid: str, target_types: tuple[str, ...]) -> str | None:
        seen = {nid}
        q = [nid]
        while q:
            cur = q.pop(0)
            for parent in rev.get(cur, []):
                if parent in seen:
                    continue
                seen.add(parent)
                n = g.nodes.get(parent)
                if n and n.type in target_types:
                    return parent
                q.append(parent)
        return None

    for nid in g.nodes:
        pm = nearest(nid, ("METHOD",))
        pf = nearest(nid, ("FILE",))
        if pm:
            parent_method[nid] = pm
        if pf:
            parent_file[nid] = pf
    return parent_method, parent_file


def _argument_nodes(g: Graph, call_id: str) -> list[Node]:
    call = g.nodes.get(call_id)
    if call is None:
        return []

    unique: dict[str, Node] = {}
    for edge in g.outgoing(call_id, {"ARGUMENT", "AST"}):
        node = g.nodes.get(edge.target)
        if node is None or node.type in {"BLOCK", "METHOD_RETURN"}:
            continue
        unique.setdefault(node.id, node)

    vals = list(unique.values())
    vals.sort(
        key=lambda n: (
            get_property(
                n, "derived.argument_index", get_property(n, "argumentIndex", 10_000)
            ),
            n.id,
        )
    )
    return vals


_ORDER_SENSITIVE_NUMERIC_CALLS = {
    "<operator>.subtraction",
    "<operator>.division",
    "<operator>.modulo",
    "<operator>.shiftLeft",
    "<operator>.shiftRight",
}


def _has_trusted_argument_order(g: Graph, call_id: str) -> bool:
    """Return whether operand order is supported by graph evidence."""
    call = g.nodes.get(call_id)
    if call is None:
        return False

    edges = [e for e in g.outgoing(call_id, {"ARGUMENT"}) if e.target in g.nodes]
    if len(edges) < 2:
        return False

    completeness = str(g.metadata.get("completeness", "declared")).lower()
    parse_ok = str(g.metadata.get("parse_health", "OK")).upper() == "OK"

    if completeness in {"full_export", "declared"} and parse_ok:
        return True

    indices = []
    for edge in edges:
        index = edge.properties.get(
            "argumentIndex", edge.properties.get("ARGUMENT_INDEX")
        )
        if index is None:
            return False
        try:
            indices.append(int(index))
        except (TypeError, ValueError):
            return False

    return len(set(indices)) == len(edges) and set(indices) == set(
        range(1, len(edges) + 1)
    )


def _numeric_from_node(
    g: Graph, node_id: str, seen: set[str] | None = None
) -> tuple[int | float | None, str | None]:
    seen = set() if seen is None else seen
    if node_id in seen:
        return None, None
    seen.add(node_id)
    n = g.nodes.get(str(node_id))
    if n is None:
        return None, None
    direct = get_property(n, "derived.numeric_value", None)
    if (
        direct is not None
        and isinstance(direct, (int, float))
        and not isinstance(direct, bool)
    ):
        return direct, "DIRECT_LITERAL"
    if n.type == "LITERAL":
        x = _num(n.get("code", n.get("CODE")))
        if x is not None:
            return x, "DIRECT_LITERAL"
    if n.type != "CALL":
        return None, None
    name = str(n.get("name", n.get("NAME", "")) or "")
    fn = _NUMERIC_CALLS.get(name)
    if fn is None:
        return None, None
    if name in _ORDER_SENSITIVE_NUMERIC_CALLS and not _has_trusted_argument_order(
        g, n.id
    ):
        return None, None
    args = _argument_nodes(g, n.id)
    values = []
    for arg in args:
        val, _proof = _numeric_from_node(g, arg.id, seen)
        if val is None:
            return None, None
        values.append(val)
    try:
        if name in {"<operator>.minus", "<operator>.plus"} and len(values) >= 1:
            return fn(values[0]), "DERIVED_EXPRESSION"
        if len(values) == 2:
            return fn(values[0], values[1]), "DERIVED_EXPRESSION"
    except Exception:
        return None, None
    return None, None


def _parse_scanf_has_unbounded_s(code: str) -> bool:

    code = code.replace('\\"', '"')
    for m in re.finditer(r"%(?:[0-9]+)?(?:\[[^]]*\]|s)", code):
        token = m.group(0)
        if token.startswith("%s") or token.startswith("%["):
            if not re.match(r"%[0-9]", token):
                return True
    return False


def _call_info(node: Node) -> dict[str, Any]:
    name = node.get("name") or node.get("NAME")
    mf = node.get("methodFullName") or node.get("METHOD_FULL_NAME")
    code = str(node.get("code", "") or "")
    lname = str(name or "").split(".")[-1]
    d = {
        "is_call": True,
        "call_name": str(name or ""),
        "call_full_name": str(mf or name or ""),
    }

    fixed = {"memcpy", "memmove", "strncpy", "wmemcpy", "wmemmove", "wcsncpy"}
    unbounded = {"strcpy", "strcat", "wcscpy", "wcscat", "gets", "sprintf", "vsprintf"}
    bounded = {
        "snprintf",
        "vsnprintf",
        "strlcpy",
        "strlcat",
        "strncpy_s",
        "strcpy_s",
        "memcpy_s",
        "memmove_s",
    }
    input_unbounded = {"gets", "scanf", "fscanf", "sscanf"}
    allocation = {"malloc", "calloc", "realloc", "aligned_alloc", "alloca", "_alloca"}
    d["memory_write_like"] = (
        str(name or "") in fixed | unbounded | bounded
        or lname in fixed | unbounded | bounded
    )
    d["fixed_extent_write_like"] = str(name or "") in fixed or lname in fixed
    wide_fixed = {"wmemcpy", "wmemmove", "wcsncpy"}
    byte_fixed = {"memcpy", "memmove", "strncpy"}
    d["wide_fixed_extent_write_like"] = (
        str(name or "") in wide_fixed or lname in wide_fixed
    )
    d["write_extent_unit"] = (
        "ELEMENTS"
        if d["wide_fixed_extent_write_like"]
        else "BYTES"
        if str(name or "") in byte_fixed or lname in byte_fixed
        else None
    )
    d["unbounded_write_like"] = str(name or "") in unbounded or lname in unbounded
    d["bounded_write_like"] = str(name or "") in bounded or lname in bounded
    d["input_operation_like"] = (
        str(name or "") in input_unbounded or lname in input_unbounded
    )
    d["allocation_like"] = str(name or "") in allocation or lname in allocation
    d["memory_region"] = "HEAP" if d["allocation_like"] else None
    d["format_write_like"] = str(name or "") in {
        "sprintf",
        "vsprintf",
        "snprintf",
        "vsnprintf",
    } or lname in {"sprintf", "vsprintf", "snprintf", "vsnprintf"}
    d["argument_role_model"] = {
        "memcpy": {1: "destination", 2: "source", 3: "extent"},
        "memmove": {1: "destination", 2: "source", 3: "extent"},
        "wmemcpy": {1: "destination", 2: "source", 3: "extent"},
        "wmemmove": {1: "destination", 2: "source", 3: "extent"},
        "strncpy": {1: "destination", 2: "source", 3: "extent"},
        "wcsncpy": {1: "destination", 2: "source", 3: "extent"},
        "strcpy": {1: "destination", 2: "source"},
        "strcat": {1: "destination", 2: "source"},
        "wcscpy": {1: "destination", 2: "source"},
        "wcscat": {1: "destination", 2: "source"},
        "gets": {1: "destination"},
        "sprintf": {1: "destination", 2: "format"},
        "vsprintf": {1: "destination", 2: "format", 3: "va_list"},
        "snprintf": {1: "destination", 2: "destination_size", 3: "format"},
        "vsnprintf": {
            1: "destination",
            2: "destination_size",
            3: "format",
            4: "va_list",
        },
        "strcpy_s": {1: "destination", 2: "destination_size", 3: "source"},
        "strncpy_s": {1: "destination", 2: "destination_size", 3: "source", 4: "count"},
        "memcpy_s": {1: "destination", 2: "destination_size", 3: "source", 4: "count"},
        "memmove_s": {1: "destination", 2: "destination_size", 3: "source", 4: "count"},
        "malloc": {1: "allocation_size"},
        "calloc": {1: "element_count", 2: "element_size"},
        "realloc": {1: "old_pointer", 2: "allocation_size"},
        "aligned_alloc": {1: "alignment", 2: "allocation_size"},
        "alloca": {1: "allocation_size"},
        "_alloca": {1: "allocation_size"},
        "scanf": {1: "format"},
        "fscanf": {1: "stream", 2: "format"},
        "sscanf": {1: "input", 2: "format"},
    }.get(str(name or ""), {}).copy()
    if str(name or "") in {"scanf", "fscanf", "sscanf"} or lname in {
        "scanf",
        "fscanf",
        "sscanf",
    }:
        d["unbounded_input_like"] = _parse_scanf_has_unbounded_s(code)

        d["destination_argument_index"] = {"scanf": 2, "fscanf": 3, "sscanf": 3}.get(
            lname
        )
    if str(name or "") == "gets" or lname == "gets":
        d["unbounded_input_like"] = True
        d["destination_argument_index"] = 1
    if str(name or "") in {
        "strcpy",
        "strcat",
        "wcscpy",
        "wcscat",
        "gets",
        "sprintf",
        "vsprintf",
    }:
        d["write_extent_mode"] = "UNBOUNDED"
    elif str(name or "") in fixed:
        d["write_extent_mode"] = "FIXED"
    elif str(name or "") in bounded:
        d["write_extent_mode"] = "BOUNDED"
    if d["allocation_like"]:
        d["allocation_role"] = "ALLOCATES_MEMORY"
    if "sizeof" in code:
        d["has_sizeof_expression"] = True
    return d


def get_property(node: Node | None, key: str, default: Any = None) -> Any:
    if node is None:
        return default
    if key.startswith("derived."):
        cur: Any = node.properties.get("derived", {})
        for part in key.split(".")[1:]:
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur
    return node.get(key, default)


def _infer_argument_indices(g: Graph) -> dict[str, dict[str, Any]]:
    """Infer argument index and semantic argument role conservatively.

    Explicit edge/node evidence always wins. Role names come only from the built-in
    call model in ``_call_info``; ordinal fallback is limited to the index itself.
    """
    provenance: dict[str, dict[str, Any]] = {}
    graph_complete = str(g.metadata.get("completeness", "declared")).lower() in {
        "full_export",
        "declared",
    }
    parse_ok = str(g.metadata.get("parse_health", "OK")).upper() == "OK"
    can_infer_by_ordinal = graph_complete and parse_ok
    for call in (n for n in g.nodes.values() if n.type == "CALL"):
        args = [e for e in g.outgoing(call.id, {"ARGUMENT"}) if e.target in g.nodes]
        args.sort(
            key=lambda e: (
                e.properties.get(
                    "argumentIndex", e.properties.get("ARGUMENT_INDEX", 10_000)
                ),
                e.id or "",
            )
        )
        role_model = _call_info(call).get("argument_role_model", {}) or {}
        for index, e in enumerate(args, start=1):
            target = g.nodes[e.target]
            d = dict(target.properties.get("derived") or {})
            explicit = e.properties.get("argumentIndex")
            if explicit is None:
                explicit = e.properties.get("ARGUMENT_INDEX")
            inferred = explicit is None
            try:
                idx = int(explicit) if explicit is not None else index
            except (TypeError, ValueError):
                idx = index
                inferred = True

            if inferred and not can_infer_by_ordinal:
                role = None
                provenance_basis = (
                    "UNKNOWN:argument_index_inference_suppressed_on_incomplete_graph"
                )
            else:
                d.setdefault("argument_index", idx)
                role = role_model.get(idx)
                provenance_basis = (
                    "DERIVED:argument_edge_property"
                    if explicit is not None
                    else "DERIVED:argument_edge_order"
                )

            lname = str(call.get("name", "") or "").split(".")[-1]
            if role is None and lname in {"sprintf", "vsprintf"} and idx >= 3:
                code = str(call.get("code", "") or "")
                if "%" in code:
                    role = "source"
            if role is not None and (not inferred or can_infer_by_ordinal):
                d.setdefault("argument_role", role)
            target.properties["derived"] = d
            prov = dict(target.properties.get("derived_provenance") or {})
            prov.setdefault("argument_index", provenance_basis)
            if role is not None and (not inferred or can_infer_by_ordinal):
                prov.setdefault("argument_role", "DERIVED:call_argument_role_model")
            target.properties["derived_provenance"] = prov
            provenance[target.id] = {
                "call": call.id,
                "argument_index": idx,
                "argument_role": role,
                "basis": prov["argument_index"],
            }
    return provenance


def _range_from_node(
    g: Graph, node_id: str, seen: set[str] | None = None
) -> tuple[float | int, float | int, str] | None:
    seen = set() if seen is None else seen
    nid = str(node_id)
    if nid in seen:
        return None
    seen.add(nid)
    n = g.nodes.get(nid)
    if n is None:
        return None

    for explicit in (
        get_property(n, "derived.range", None),
        n.properties.get("range"),
    ):
        if isinstance(explicit, dict) and "lower" in explicit and "upper" in explicit:
            lo, hi = _num(explicit.get("lower")), _num(explicit.get("upper"))
            if lo is not None and hi is not None and lo <= hi:
                return lo, hi, str(explicit.get("proof", "EXPLICIT_RANGE"))
    val = get_property(n, "derived.numeric_value", None)
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return val, val, "EXACT_VALUE"
    if n.type == "LITERAL":
        v = _num(n.get("code", n.get("CODE")))
        if v is not None:
            return v, v, "LITERAL"

    for e in g.incoming(nid, {"REACHING_DEF"}):
        r = _range_from_node(g, e.source, seen)
        if r:
            return r[0], r[1], "REACHING_DEF:" + r[2]
    if n.type == "CALL" and str(n.get("name", "")) in _NUMERIC_CALLS:
        name = str(n.get("name", ""))
        if name in _ORDER_SENSITIVE_NUMERIC_CALLS and not _has_trusted_argument_order(
            g, n.id
        ):
            return None
        args = _argument_nodes(g, n.id)
        ranges = [_range_from_node(g, a.id, seen) for a in args]
        if ranges and all(r is not None for r in ranges):
            name = str(n.get("name", ""))
            rs = [(r[0], r[1]) for r in ranges if r]
            try:
                if (
                    name
                    in {
                        "<operator>.addition",
                        "<operator>.subtraction",
                        "<operator>.multiplication",
                    }
                    and len(rs) == 2
                ):
                    a0, a1 = rs[0]
                    b0, b1 = rs[1]
                    if name == "<operator>.addition":
                        return a0 + b0, a1 + b1, "INTERVAL_ARITHMETIC"
                    if name == "<operator>.subtraction":
                        return a0 - b1, a1 - b0, "INTERVAL_ARITHMETIC"
                    vals = [a0 * b0, a0 * b1, a1 * b0, a1 * b1]
                    return min(vals), max(vals), "INTERVAL_ARITHMETIC"
                if name in {"<operator>.minus", "<operator>.plus"} and len(rs) >= 1:
                    a0, a1 = rs[0]
                    return (
                        (-a1, -a0, "INTERVAL_ARITHMETIC")
                        if name.endswith("minus")
                        else (a0, a1, "INTERVAL_ARITHMETIC")
                    )
            except Exception:
                return None
    return None


def node_value_range(g: Graph, node_id: str) -> dict[str, Any] | None:
    r = _range_from_node(g, node_id)
    if not r:
        return None
    return {"lower": r[0], "upper": r[1], "proof": r[2]}


def _infer_object_id(
    g: Graph, node: Node, parent_methods: dict[str, str]
) -> tuple[str | None, str | None]:
    d = node.properties.get("derived") or {}
    if d.get("object_id"):
        return str(d["object_id"]), str(d.get("object_id_proof", "EXPLICIT"))

    raw_oid = node.get("object_id")
    if raw_oid is not None:
        return str(raw_oid), str(node.get("object_id_proof", "EXPLICIT"))

    name = node.get("name")
    if not name or node.type not in {
        "LOCAL",
        "IDENTIFIER",
        "METHOD_PARAMETER_IN",
        "METHOD_PARAMETER_OUT",
        "MEMBER",
    }:
        return None, None
    pm = parent_methods.get(node.id, d.get("parent_method_node", ""))
    return f"{pm or 'GLOBAL'}::{name}", "STRUCTURAL_NAME"


def _capacity_from_call(g: Graph, node: Node) -> tuple[Any, str | None, str | None]:
    name = str(node.get("name", "") or "")
    args = _argument_nodes(g, node.id)
    if name in {"malloc", "alloca", "_alloca", "aligned_alloc"} and args:
        idx = 1 if name != "aligned_alloc" else 2
        a = next(
            (x for x in args if get_property(x, "derived.argument_index") == idx), None
        )
        if a:
            r = node_value_range(g, a.id)
            if r and r["lower"] == r["upper"]:
                return r["lower"], "HEAP", "ALLOC_CALL_ARG"
    if name == "calloc" and len(args) >= 2:
        rs = []
        for idx in (1, 2):
            a = next(
                (x for x in args if get_property(x, "derived.argument_index") == idx),
                None,
            )
            if not a:
                return None, None, None
            rr = node_value_range(g, a.id)
            if not rr or rr["lower"] != rr["upper"]:
                return None, None, None
            rs.append(rr["lower"])
        return rs[0] * rs[1], "HEAP", "CALLOC_PRODUCT"
    if name == "realloc" and len(args) >= 2:
        a = next(
            (x for x in args if get_property(x, "derived.argument_index") == 2), None
        )
        if a:
            r = node_value_range(g, a.id)
            if r and r["lower"] == r["upper"]:
                return r["lower"], "HEAP", "REALLOC_SIZE"
    return None, None, None


def enrich_graph(g: Graph) -> Graph:
    """Derive deterministic C/C++ facts without overwriting explicit evidence.

    Every derived fact records a compact provenance label in ``derived_provenance``.
    Raw Joern observations remain untouched. Physical stack residency is never inferred
    from LOCAL alone.
    """
    pm, pf = _parent_lookup(g)
    argument_index_provenance = _infer_argument_indices(g)
    for n in g.nodes.values():
        d = dict(n.properties.get("derived") or {})
        prov = dict(n.properties.get("derived_provenance") or {})
        d.setdefault("node_kind", n.type)
        aliases = {
            "NAME": "name",
            "name": "name",
            "CODE": "code",
            "code": "code",
            "TYPE_FULL_NAME": "type_full_name",
            "typeFullName": "type_full_name",
            "METHOD_FULL_NAME": "method_full_name",
            "methodFullName": "method_full_name",
            "ARGUMENT_INDEX": "argument_index",
            "argumentIndex": "argument_index",
        }
        for raw, out in aliases.items():
            if raw in n.properties and out not in d:
                d[out] = n.properties[raw]
                prov.setdefault(out, f"RAW:{raw}")

        array = _array_info(n)
        for k, v in array.items():
            if k not in d:
                d[k] = v
                prov.setdefault(k, f"DERIVED:array:{v if k == 'length' else 'shape'}")

        storage = _derive_storage(n)
        for k, v in storage.items():
            if k not in d:
                d[k] = v
                prov.setdefault(k, f"DERIVED:storage:{v}")

        if d.get("is_array") and d.get("length") is not None:
            d.setdefault("element_count", d.get("length"))
            d.setdefault("memory_capacity_elements", d.get("length"))
            prov.setdefault("memory_capacity_elements", "DERIVED:array_length")
            if d.get("byte_capacity_known"):
                d.setdefault("memory_capacity", d.get("length"))
                prov.setdefault("memory_capacity", "DERIVED:array_length:char_like")
                d.setdefault("capacity_unit", "BYTES")
                d.setdefault("capacity_proof", d.get("length_proof", "DIRECT_LITERAL"))
            else:
                d.setdefault("capacity_unit", "ELEMENTS")
                d.setdefault("byte_capacity_known", False)
            d.setdefault("memory_region", "LOCAL_OR_GLOBAL")
        if "storage_duration" in d and d.get("storage_duration") == "STATIC_LOCAL":
            d.setdefault("memory_region", "STATIC")
            d.setdefault(
                "memory_capacity_known", bool(d.get("memory_capacity") is not None)
            )
        if "storage_duration" in d and d.get("storage_duration") == "AUTOMATIC":
            d.setdefault("memory_region", "AUTOMATIC")
        if n.type == "CALL" and d.get("allocation_like"):
            cap, region, proof = _capacity_from_call(g, n)
            if cap is not None and "memory_capacity" not in d:
                d["memory_capacity"] = cap
                prov["memory_capacity"] = "DERIVED:" + str(proof)
            if region and "memory_region" not in d:
                d["memory_region"] = region
                prov["memory_region"] = "DERIVED:allocation_semantics"
            d.setdefault("memory_capacity_known", cap is not None)
        if n.type in {"METHOD_PARAMETER_IN", "METHOD_PARAMETER_OUT"}:
            if "memory_capacity" not in d and d.get("array_length") is not None:
                d["memory_capacity"] = d.get("array_length")

        if n.type == "LITERAL":
            num = _num(n.get("code", n.get("CODE")))
            if num is not None and "numeric_value" not in d:
                d["numeric_value"] = num
                prov["numeric_value"] = "DERIVED:literal"
            sl = _string_length(str(n.get("code", n.get("CODE", "")) or ""))
            if sl is not None and "string_length" not in d:
                d["string_length"] = sl
                prov["string_length"] = "DERIVED:string_literal_length"

        if n.type == "CALL":
            call = _call_info(n)
            for k, v in call.items():
                if k not in d:
                    d[k] = v
                    prov[k] = "DERIVED:call_semantics"

            source_names = {
                "gets",
                "scanf",
                "fscanf",
                "sscanf",
                "recv",
                "recvfrom",
                "read",
                "fgets",
                "fread",
                "getenv",
            }
            lname = str(n.get("name", "") or "").split(".")[-1]
            if lname in source_names:
                d.setdefault("potential_external_input", True)
                d.setdefault("source_origin_kind", "DIRECT_INPUT_API")
                prov.setdefault("potential_external_input", "DERIVED:known_input_api")
                prov.setdefault("source_origin_kind", "DERIVED:known_input_api")
            if "numeric_value" not in d:
                val, proof = _numeric_from_node(g, n.id)
                if val is not None:
                    d["numeric_value"] = val
                    d["numeric_proof"] = proof
                    prov["numeric_value"] = "DERIVED:numeric_expression"

        if n.id in pm and "parent_method_node" not in d:
            d["parent_method_node"] = pm[n.id]
            prov["parent_method_node"] = "DERIVED:structural_parent"
        if n.id in pf and "parent_file_node" not in d:
            d["parent_file_node"] = pf[n.id]
            prov["parent_file_node"] = "DERIVED:structural_parent"
        if n.get("IS_EXTERNAL") is not None and "is_external" not in d:
            d["is_external"] = bool(n.get("IS_EXTERNAL"))
            prov["is_external"] = "RAW:IS_EXTERNAL"

        if "range" not in d:
            raw_range = n.properties.get("range")
            if (
                isinstance(raw_range, dict)
                and "lower" in raw_range
                and "upper" in raw_range
            ):
                lo = _num(raw_range.get("lower"))
                hi = _num(raw_range.get("upper"))
                if lo is not None and hi is not None and lo <= hi:
                    d["range"] = {
                        "lower": lo,
                        "upper": hi,
                        "proof": str(raw_range.get("proof", "EXPLICIT_RANGE")),
                    }
                    prov["range"] = "RAW:range"

        if "range" not in d:
            rr = node_value_range(g, n.id)
            if rr:
                d["range"] = rr
                prov["range"] = "DERIVED:interval"
        if "object_id" not in d:
            oid, basis = _infer_object_id(g, n, pm)
            if oid:
                d["object_id"] = oid
                d.setdefault("object_id_proof", basis)
                prov["object_id"] = "DERIVED:object_identity:" + str(basis)
        if d.get("memory_capacity") is not None:
            d.setdefault("memory_capacity_known", True)
            d.setdefault("capacity_unit", "BYTES")

        n.properties["derived"] = d
        n.properties["derived_provenance"] = prov

    g.metadata["semantic_enrichment"] = {
        "version": "2.0",
        "facts": [
            "array_info",
            "numeric_literal",
            "numeric_expression",
            "storage_duration",
            "parent_method",
            "parent_file",
            "call_semantics",
            "argument_roles",
            "argument_index_inference",
            "semantic_edge_aliases",
            "derived_provenance",
            "memory_capacity",
            "memory_region",
            "object_identity",
            "numeric_range",
            "copy_semantics",
            "input_operation_semantics",
        ],
        "physical_stack_inference": False,
        "semantic_edge_aliases": {
            k: sorted(v) for k, v in SEMANTIC_EDGE_ALIASES.items()
        },
        "argument_index_inference": argument_index_provenance,
        "principle": "raw observations are preserved; explicit derived facts are authoritative and inferred facts are fill-only",
    }
    return g


def semantic_edge_types(
    relation: str | None, raw_edge_types: list[str] | None = None
) -> set[str] | None:
    if relation:
        rel = str(relation).upper()
        return set(SEMANTIC_EDGE_ALIASES.get(rel, {rel}))
    if raw_edge_types:
        return {str(x).upper() for x in raw_edge_types}
    return None


def relation_for_edge(edge_type: str) -> list[str]:
    et = str(edge_type).upper()
    return sorted(
        [name for name, aliases in SEMANTIC_EDGE_ALIASES.items() if et in aliases]
    )


def same_object_call_binding_proof(
    graph: Graph, source: Node, target: Node
) -> dict[str, Any] | None:
    if source.type.upper() != "IDENTIFIER":
        return None

    parameters: dict[str, Node] = {}

    for edge in graph.outgoing(source.id, {"REF"}):
        node = graph.nodes.get(edge.target)
        if node is not None and node.type.upper() == "METHOD_PARAMETER_IN":
            parameters[node.id] = node

    for edge in graph.incoming(source.id, {"REF"}):
        node = graph.nodes.get(edge.source)
        if node is not None and node.type.upper() == "METHOD_PARAMETER_IN":
            parameters[node.id] = node

    if len(parameters) != 1:
        return None

    parameter = next(iter(parameters.values()))
    raw_parameter_index = get_property(parameter, "index", None)

    def positive_index(value: Any) -> int | None:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, float) and not value.is_integer():
            return None
        if isinstance(value, str) and not value.strip().isdigit():
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    parameter_index = positive_index(raw_parameter_index)
    if parameter_index is None:
        return None

    parameter_owner = get_property(parameter, "derived.parent_method_node", None)
    source_owner = get_property(source, "derived.parent_method_node", None)
    target_owner = get_property(target, "derived.parent_method_node", None)

    if parameter_owner is None or source_owner is None or target_owner is None:
        return None
    if str(source_owner) != str(parameter_owner):
        return None

    callee = graph.nodes.get(str(parameter_owner))
    caller = graph.nodes.get(str(target_owner))
    if callee is None or callee.type.upper() != "METHOD":
        return None
    if caller is None or caller.type.upper() != "METHOD":
        return None

    parameter_refs = graph.matching_edges(source.id, parameter.id, {"REF"}, True)
    if not parameter_refs:
        return None

    for call in graph.nodes.values():
        if call.type.upper() != "CALL":
            continue

        call_owner = get_property(call, "derived.parent_method_node", None)
        if call_owner is None or str(call_owner) != str(target_owner):
            continue

        call_edges = graph.matching_edges(call.id, str(parameter_owner), {"CALL"})
        if not call_edges:
            continue

        for argument_edge in graph.outgoing(call.id, {"ARGUMENT"}):
            actual = graph.nodes.get(argument_edge.target)
            if actual is None:
                continue

            raw_argument_index = get_property(actual, "derived.argument_index", None)
            argument_index = positive_index(raw_argument_index)
            if argument_index is None:
                continue

            provenance = get_property(actual, "derived_provenance.argument_index", None)
            if provenance is not None and str(provenance).startswith("UNKNOWN:"):
                continue

            if argument_index != parameter_index:
                continue

            actual_owner = get_property(actual, "derived.parent_method_node", None)
            if actual_owner is None or str(actual_owner) != str(target_owner):
                continue

            object_refs = graph.matching_edges(actual.id, target.id, {"REF"}, True)
            if not object_refs:
                continue

            parameter_ref = parameter_refs[0]
            call_edge = call_edges[0]
            object_ref = object_refs[0]

            return {
                "proof": "CALL_ARGUMENT_PARAMETER_REF",
                "source_expression": source.id,
                "source_parameter_ref": {
                    "source": parameter_ref.source,
                    "target": parameter_ref.target,
                    "type": parameter_ref.type,
                },
                "callsite": call.id,
                "call_to_callee": {
                    "source": call_edge.source,
                    "target": call_edge.target,
                    "type": call_edge.type,
                },
                "formal_parameter": parameter.id,
                "parameter_index": parameter_index,
                "actual_argument": actual.id,
                "argument_index": argument_index,
                "call_argument": {
                    "source": argument_edge.source,
                    "target": argument_edge.target,
                    "type": argument_edge.type,
                },
                "object_reference": {
                    "source": object_ref.source,
                    "target": object_ref.target,
                    "type": object_ref.type,
                },
                "target_object": target.id,
            }

    return None
