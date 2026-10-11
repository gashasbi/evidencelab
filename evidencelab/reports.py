from __future__ import annotations
import html, json
from typing import Any


def sym(status: str, context: str = "claim") -> str:
    if context == "counter":
        return {
            "PROVEN": "⚠",
            "DISPROVEN": "✓",
            "UNKNOWN": "?",
            "NOT_APPLICABLE": "—",
        }.get(status, "•")
    return {
        "PROVEN": "✓",
        "DISPROVEN": "✗",
        "UNKNOWN": "?",
        "NOT_APPLICABLE": "—",
        "MATCH": "✓",
        "NO_MATCH": "✗",
        "PARTIAL": "⚠",
        "PASS": "✓",
        "FAIL": "✗",
    }.get(status, "•")


def render_text(p: dict[str, Any]) -> str:
    lines = ["=" * 92, "EvidenceLab Validation Report", "=" * 92]
    pat = p.get("pattern", {})
    lines += [
        f"CWE: {pat.get('cwe')}",
        f"Pattern: {pat.get('id')}",
        f"Overall: {sym(p.get('status', 'UNKNOWN'))} {p.get('status')}",
        "",
    ]
    if "graph" in p:
        lines += [
            "INPUT GRAPH",
            json.dumps(p["graph"], ensure_ascii=False, indent=2),
            "",
        ]
    if "audit" in p:
        lines.append("PATTERN AUDIT")
        fs = p["audit"].get("findings", [])
        lines.append(" ✓ no audit findings" if not fs else "")
        for f in fs:
            lines.append(
                f" {sym('FAIL' if f['severity'] == 'ERROR' else 'PARTIAL')} {f['id']} [{f['severity']}]: {f['message']}"
            )
        lines.append("")
    if "match" in p:
        m = p["match"]
        lines += ["EVIDENCE MATCH", f" {sym(m.get('status'))} {m.get('status')}"]
        for w in m.get("witnesses", []):
            lines.append(
                f" Witness {w['witness_id']}: {sym(w['status'])} {w['status']} bindings={w.get('bindings', {})} combinations={w.get('combination_count', 0)}"
            )
            for c in w.get("claims", []):
                lines.append(
                    f"   {sym(c['status'])} {c['claim_id']} [{c['kind']}]: {c['explanation']}"
                )
            for c in w.get("counter_evidence", []):
                lines.append(
                    f"   {sym(c['status'], 'counter')} COUNTER {c['claim_id']} [{c['kind']}]: {c['explanation']}"
                )
            if w.get("rejection_summary"):
                lines.append(f"   rejection_summary={w['rejection_summary']}")
        for c in m.get("claims", []):
            lines.append(
                f" {sym(c['status'])} {c['claim_id']} [{c['kind']}]: {c['explanation']}"
            )
        for c in m.get("counter_evidence", []):
            lines.append(
                f" {sym(c['status'], 'counter')} COUNTER {c['claim_id']} [{c['kind']}]: {c['explanation']}"
            )
        lines.append("")
    if "metrics" in p:
        lines += [
            "BENCHMARK METRICS",
            json.dumps(p["metrics"], ensure_ascii=False, indent=2),
            "",
        ]
    if "benchmark" in p:
        lines += [
            "BENCHMARK COVERAGE",
            json.dumps(p["benchmark"], ensure_ascii=False, indent=2),
            "",
        ]
    if "gate_errors" in p:
        lines += (
            ["RESEARCH GATES"]
            + (
                [f" ✗ {x}" for x in p["gate_errors"]]
                if p["gate_errors"]
                else [" ✓ all configured gates passed"]
            )
            + [""]
        )
    return "\n".join(lines + ["=" * 92])


def render_markdown(p: dict[str, Any]) -> str:
    out = [
        "# EvidenceLab Validation Report",
        "",
        f"**CWE:** `{p.get('pattern', {}).get('cwe')}`",
        f"**Pattern:** `{p.get('pattern', {}).get('id')}`",
        f"**Status:** `{p.get('status')}`",
        "\n",
    ]
    if "audit" in p:
        out += [
            "## Pattern Audit",
            "",
            "| Severity | ID | Message |",
            "|---|---|---|",
            *(
                f"| {x['severity']} | `{x['id']}` | {x['message']} |"
                for x in p["audit"].get("findings", [])
            ),
            "",
        ]
    if "match" in p:
        out += [
            "## Evidence Match",
            "",
            f"**{p['match']['status']}**",
            "",
            "| Status | Claim | Type | Explanation |",
            "|---|---|---|---|",
        ]
        for w in p["match"].get("witnesses", []):
            for c in w.get("claims", []):
                out.append(
                    f"| {sym(c['status'])} | `{c['claim_id']}` | {c['kind']} | {c['explanation']} |"
                )
            for c in w.get("counter_evidence", []):
                out.append(
                    f"| {sym(c['status'], 'counter')} | `COUNTER {c['claim_id']}` | {c['kind']} | {c['explanation']} |"
                )
        out.append("")
    if "metrics" in p:
        out += [
            "## Benchmark Metrics",
            "",
            "```json",
            json.dumps(p["metrics"], indent=2),
            "```",
            "",
        ]
    if "gate_errors" in p:
        out += [
            "## Research Gates",
            "",
            "❌ **FAIL**" if p["gate_errors"] else "✅ **PASS**",
            "",
            *(f"- {x}" for x in p["gate_errors"]),
            "",
        ]
    return "\n".join(out)


def render_html(p: dict[str, Any]) -> str:
    title = f"EvidenceLab — {p.get('pattern', {}).get('cwe', 'Validation')}"
    status = p.get("status", "UNKNOWN")
    body = html.escape(render_text(p))
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>body{{font-family:Inter,system-ui,sans-serif;background:#0b1220;color:#e5e7eb;margin:0}}main{{max-width:1250px;margin:auto;padding:32px}}header{{display:flex;justify-content:space-between;align-items:center;gap:20px}}.badge{{padding:8px 14px;border-radius:999px;background:#172033;font-weight:700}}.card{{margin-top:22px;background:#111827;border:1px solid #24304a;border-radius:16px;padding:20px}}pre{{white-space:pre-wrap;line-height:1.55;overflow:auto}}.muted{{color:#94a3b8}}</style></head><body><main><header><div><h1>{html.escape(title)}</h1><div class='muted'>Research-grade graph evidence evaluation</div></div><div class='badge'>{html.escape(status)}</div></header><div class='card'><pre>{body}</pre></div></main></body></html>"""
