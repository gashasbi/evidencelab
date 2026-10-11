from __future__ import annotations
from pathlib import Path
from typing import Any
import json, re, time
from . import SCHEMA_VERSION


def _load_task(root: Path) -> dict[str, Any]:
    p = root / "task.json"
    if not p.is_file():
        raise ValueError(f"research task not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    cwe = str(raw.get("cwe", "")).upper()
    if not re.fullmatch(r"CWE-\d+", cwe):
        raise ValueError("task.cwe must look like CWE-123")
    return raw


def init_evidence_family(
    research_root: str | Path,
    family_id: str,
    name: str | None = None,
    research_question: str | None = None,
    version: str = "1.0.0",
    overwrite: bool = False,
) -> Path:
    root = Path(research_root).resolve()
    task = _load_task(root)
    fid = re.sub(r"[^a-z0-9._-]+", "-", family_id.lower()).strip("-")
    if not fid:
        raise ValueError("family_id cannot be empty")
    family = root / "families" / fid
    if family.exists() and any(family.iterdir()) and not overwrite:
        raise FileExistsError(f"family already exists and is not empty: {family}")
    family.mkdir(parents=True, exist_ok=True)
    cwe = str(task["cwe"]).upper()
    rq = (
        research_question
        or task.get("research_question")
        or f"What graph-observable evidence is sufficient for {cwe} family {fid}?"
    )
    validation = task.get("validation", {}) or {}
    pattern = {
        "schema_version": SCHEMA_VERSION,
        "pattern_id": f"{cwe.lower()}-{fid}",
        "cwe": cwe,
        "name": name or fid.replace("-", " ").title(),
        "version": version,
        "language": str(task.get("language", "C/C++")),
        "description": "Research draft. Complete the evidence definition from recorded experiments before publication use.",
        "unknown_policy": "unknown",
        "counter_unknown_policy": "block_match",
        "metadata": {
            "research_question": rq,
            "evidence_definition_version": SCHEMA_VERSION,
            "evidence_class": "DRAFT",
            "family_semantics": "Define a single independently testable evidence mechanism; do not mix incompatible witness semantics.",
        },
        "provenance": [],
        "coverage": {
            "required_dimensions": list(task.get("expected_evidence_dimensions", [])),
            "minimum_public_cases": int(validation.get("minimum_public_cases", 120)),
            "minimum_hidden_cases": int(validation.get("minimum_hidden_cases", 120)),
        },
        "concepts": {},
        "slots": {},
        "claims": [],
        "counter_evidence": [],
        "witnesses": [],
        "evidence_contract": {
            "unknown_policy": "unknown",
            "counter_unknown_policy": "block_match",
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
            "required_analysis_dimensions": [
                "dataflow",
                "object_identity",
                "control_flow",
            ],
        },
        "semantic_contract": {
            "canonical_graph_required": True,
            "analyzer_independent": True,
            "required_analysis_dimensions": [
                "dataflow",
                "object_identity",
                "control_flow",
            ],
        },
        "relevance_policy": {
            "minimum_sufficient_witness": True,
            "max_path_hops": 12,
            "reject_unrelated_bindings": True,
        },
        "path_budget": {"max_hops": 12, "max_paths_per_claim": 100},
        "provenance_policy": {
            "derived_facts_require_inputs": True,
            "literature_linkage": True,
            "artifact_hashes": True,
            "require_query_hash": True,
        },
    }
    (family / "pattern.json").write_text(
        json.dumps(pattern, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for sub in (
        "tests/positive",
        "tests/negative",
        "tests/unknown",
        "tests/adversarial",
        "mutations",
        "observations",
        "provenance",
    ):
        (family / sub).mkdir(parents=True, exist_ok=True)
    benchmark = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-benchmark",
        "manifest_id": f"{cwe.lower()}-{fid}-public-{SCHEMA_VERSION}",
        "partition": "public",
        "dataset": {
            "name": "research-family-template",
            "family_id": fid,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "cases": [],
    }
    (family / "benchmark.json").write_text(
        json.dumps(benchmark, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (family / "README.md").write_text(
        f"# {cwe}: {name or fid}\n\n"
        f"Research question: {rq}\n\n"
        "This Family becomes executable only after its hypothesis, observations, derivations, witness definition, counter-evidence, corpus, and limitations are documented.\n\n"
        "## Required work\n"
        "- define the semantic boundary and what is explicitly not proven\n"
        "- record raw analyzer observations and their provenance\n"
        "- derive facts separately from raw observations\n"
        "- define one coherent witness binding\n"
        "- add positive, negative, UNKNOWN, counter-evidence and adversarial cases\n"
        "- validate against real-world data with repository/project/temporal splits\n"
        "- run independent witness validation and hidden evaluation\n",
        encoding="utf-8",
    )
    (family / "limitations.md").write_text(
        "# Limitations and coverage gaps\n\n"
        "Document known false negatives, ambiguous cases, analyzer limitations, unsupported language constructs, and evidence that must remain UNKNOWN.\n",
        encoding="utf-8",
    )
    return family
