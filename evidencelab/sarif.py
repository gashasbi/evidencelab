from __future__ import annotations
import json
from pathlib import Path
from typing import Any


def _location_from_node(node: dict[str, Any]) -> dict[str, Any] | None:
    props = node.get("properties", {}) or {}
    file_name = (
        props.get("filename")
        or props.get("FILENAME")
        or props.get("parentFile")
        or props.get("parent_file")
    )
    line = props.get("lineNumber") or props.get("LINE_NUMBER") or props.get("line")
    col = props.get("columnNumber") or props.get("COLUMN_NUMBER") or props.get("column")
    if not file_name or not line:
        return None
    region = {"startLine": int(line)}
    if col:
        region["startColumn"] = int(col)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": str(file_name)},
            "region": region,
        }
    }


def validation_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    pat = report.get("pattern", {})
    match = report.get("match", {})
    rule_id = str(pat.get("id", "evidencelab.pattern"))
    cwe = str(pat.get("cwe", "CWE-0"))
    results: list[dict[str, Any]] = []
    bindings = []
    for witness in match.get("witnesses", []):
        if witness.get("status") != "MATCH":
            continue
        bindings.append(witness.get("bindings", {}))
        locs: list[dict[str, Any]] = []
        for claim in witness.get("claims", []):
            for m in claim.get("matches", []):
                if not isinstance(m, dict):
                    continue
                file_name = m.get("file")
                line = m.get("line")
                col = m.get("column")
                if file_name and line is not None:
                    region = {"startLine": int(line)}
                    if col is not None:
                        region["startColumn"] = int(col)
                    locs.append(
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(file_name)},
                                "region": region,
                            }
                        }
                    )
        message = f"Evidence Family {rule_id} matched for {cwe}; witness bindings: {json.dumps(witness.get('bindings', {}), sort_keys=True)}"
        item = {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": message},
            "properties": {
                "evidencelab.cwe": cwe,
                "evidencelab.witness": witness.get("witness_id"),
                "evidencelab.bindings": witness.get("bindings", {}),
                "evidencelab.proof_claims": [
                    c.get("claim_id")
                    for c in witness.get("claims", [])
                    if c.get("status") == "PROVEN"
                ],
                "evidencelab.counter_claims": [
                    c.get("claim_id") for c in witness.get("counter_evidence", [])
                ],
            },
        }
        if locs:
            item["locations"] = locs[:5]
        results.append(item)

    driver = {
        "name": "EvidenceLab",
        "version": __import__("evidencelab").__version__,
        "informationUri": "https://github.com/evidencelab/evidencelab",
        "rules": [
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(pat.get("name", rule_id))},
                "help": {"text": str(pat.get("description", "Evidence Family match."))},
                "properties": {"tags": [cwe]},
            }
        ],
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def write_sarif(report_path: str | Path, out_path: str | Path) -> Path:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    out = Path(out_path)
    out.write_text(
        json.dumps(validation_to_sarif(report), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return out
