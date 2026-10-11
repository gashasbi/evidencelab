from __future__ import annotations
from pathlib import Path
import json, re, time
from . import SCHEMA_VERSION
from typing import Any

TASK_TEMPLATE = {
    "schema_version": SCHEMA_VERSION,
    "task_id": "RESEARCH-TASK-UNSET",
    "cwe": "CWE-UNSET",
    "language": "C/C++",
    "substrate": "Joern",
    "research_question": "What graph-observable evidence is sufficient to establish the selected weakness family while distinguishing PROVEN, DISPROVEN and UNKNOWN?",
    "scope": {"in_scope": [], "out_of_scope": [], "non_goals": []},
    "hypotheses": [],
    "expected_evidence_dimensions": [
        "source_control",
        "dataflow",
        "object_identity",
        "target_state",
        "operation",
        "value_or_range",
        "control_conditions",
        "counter_evidence",
        "analysis_completeness",
        "provenance",
    ],
    "validation": {
        "public_required": True,
        "hidden_required_for_publication": True,
        "minimum_public_cases": 200,
        "minimum_hidden_cases": 160,
        "requires_adversarial_mutations": True,
        "requires_real_world_validation": True,
        "requires_group_split": True,
        "requires_temporal_split": True,
        "requires_independent_witness_validation": True,
        "requires_confidence_intervals": True,
        "requires_leakage_audit": True,
    },
    "dataset_policy": {
        "prefer_real_world": True,
        "require_source_fingerprints": True,
        "require_project_or_repository_groups": True,
        "forbid_public_hidden_overlap": True,
        "retain_dataset_license_and_provenance": True,
        "do_not_treat_synthetic_variants_as_independent_projects": True,
    },
    "claims": {
        "publication_claim_requires_hidden_validation": True,
        "point_metrics_alone_are_insufficient": True,
        "unknown_is_not_false": True,
        "evidence_quality_is_distinct_from_detection": True,
        "semantic_diversity_is_distinct_from_case_count": True,
    },
    "limitations": [],
}

README = """# EvidenceLab Research Workspace\n\nThis workspace is a reproducible environment for investigating machine-testable vulnerability evidence. It separates raw analyzer observations, semantic derivations, executable Evidence Families, benchmark construction, independent witness replay, real-world validation and evaluator-controlled hidden evaluation.\n\n## Research loop\n1. Define the CWE boundary and non-goals.\n2. Register falsifiable hypotheses.\n3. Record literature, standards and analyzer versions.\n4. Run exact analyzer queries and preserve raw observations.\n5. Derive semantic facts separately and attach provenance and replay information.\n6. Split competing mechanisms into independent Evidence Families when their evidence semantics differ.\n7. Build public cases covering positive, negative, UNKNOWN, counter-evidence, control conditions and analysis-completeness failures.\n8. Import real-world sources with their original dataset identity, repository, project, CVE and patch provenance where available.\n9. Run exact/near-duplicate and mutation-lineage checks before splitting.\n10. Use repository/project/CVE grouping and chronological evaluation where metadata permits.\n11. Validate concrete witnesses with fixed-binding semantic replay.\n12. Run public evaluation, then evaluator-controlled hidden evaluation outside this workspace.\n13. Record performance, resource use, coverage, limitations and confidence intervals.\n14. Produce a reproducibility bundle containing exact versions, hashes, commands and provenance.\n\n## Non-negotiable\n- UNKNOWN is not FALSE.\n- A definitive result requires a coherent witness.\n- Counter-evidence is evaluated against the same witness binding.\n- Derived facts retain their input provenance and derivation method.\n- Analyzer failure or incomplete analysis is not silently relabeled as a vulnerability or a safe result.\n- Public benchmark accuracy does not establish real-world generalization.\n- Duplicates, near-duplicates and one-change mutations are not independent evidence of dataset diversity.\n- Hidden validation must remain outside the public/researcher-controlled tree.\n"""


def _write_json(path: Path, value: dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def init_research_project(cwe: str, out: str | Path, overwrite: bool = False) -> Path:
    cwe = cwe.upper().strip()
    if not re.fullmatch(r"CWE-\d+", cwe):
        raise ValueError("CWE must look like CWE-123")
    root = Path(out).resolve()
    if root.exists() and any(root.iterdir()) and not overwrite:
        raise FileExistsError(f"research project is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    dirs = (
        "families",
        "evidence",
        "benchmarks/public",
        "benchmarks/hidden",
        "experiments",
        "notes",
        "queries/joern",
        "queries/tests",
        "corpus/source",
        "corpus/graphs",
        "corpus/raw",
        "corpus/imported",
        "datasets/raw",
        "datasets/imported",
        "datasets/derived",
        "reports",
        "provenance",
        "submissions",
        "splits/repository",
        "splits/chronological",
        "splits/cve",
        "mutations",
    )
    for d in dirs:
        (root / d).mkdir(parents=True, exist_ok=True)
    task = json.loads(json.dumps(TASK_TEMPLATE))
    task["task_id"] = f"{cwe.lower()}-evidence-research-001"
    task["cwe"] = cwe
    _write_json(root / "task.json", task)
    (root / "README.md").write_text(
        f"# {cwe} Evidence Research Package\n\n" + README, encoding="utf-8"
    )
    (root / "research-plan.md").write_text(
        f"""# {cwe} Evidence Research Plan\n\n## Goal\nDefine falsifiable, machine-testable Evidence Families for {cwe}.\n\n## Required research artifacts\n- CWE boundary and non-goals\n- hypothesis register\n- literature/standards register\n- raw analyzer observations\n- semantic derivations with provenance\n- executable patterns and unit tests\n- public benchmark\n- real-world benchmark\n- hidden evaluator benchmark protocol\n- leakage and lineage report\n- repository/project/CVE and chronological split manifests\n- mutation matrix\n- independent witness validation report\n- performance/resource report\n- limitations and coverage matrix\n- reproducibility/provenance bundle\n\n## Publication gate\nThe publication profile is intentionally strict. A synthetic-only package, point metrics without confidence intervals, or public-only validation is not sufficient.\n""",
        encoding="utf-8",
    )
    (root / "notes" / "literature.md").write_text(
        "# Literature and Standards\n\nRecord exact URL, access date, version, claim supported/contradicted, experiment relevance, and license/access terms.\n",
        encoding="utf-8",
    )
    (root / "notes" / "evidence-decisions.md").write_text(
        "# Evidence Decisions\n\nRecord accepted hypotheses, rejected hypotheses, counterexamples, reasons for splitting Evidence Families, and unresolved UNKNOWN cases.\n",
        encoding="utf-8",
    )
    (root / "notes" / "coverage-matrix.md").write_text(
        "# Coverage Matrix\n\nTrack evidence dimensions versus public, real-world and hidden cases. Do not equate case count with semantic diversity.\n\n| Dimension | Public | Real-world | Hidden | Notes |\n|---|---:|---:|---:|---|\n",
        encoding="utf-8",
    )
    (root / "queries" / "README.md").write_text(
        "# Analyzer Queries\n\nStore exact Joern scripts/queries, query version, command line, analyzer version, expected observations, and executable tests. A query without a test/specification should not be treated as final research evidence.\n",
        encoding="utf-8",
    )
    (root / "queries" / "joern" / "README.md").write_text(
        "# Joern Queries\n\nKeep raw CPG/data-flow queries and their exact invocation. Preserve outputs under experiments/ or provenance/.\n",
        encoding="utf-8",
    )
    (root / "queries" / "tests" / "README.md").write_text(
        "# Query Tests\n\nRecord before/after or positive/negative examples that specify the intended analyzer behavior.\n",
        encoding="utf-8",
    )
    (root / "corpus" / "README.md").write_text(
        "# Corpus\n\nUse real sources where possible. Keep external datasets outside the release when size/licensing requires it, but keep acquisition manifests, checksums and source URLs here. Every case must retain label provenance and source identity.\n",
        encoding="utf-8",
    )
    (root / "provenance" / "README.md").write_text(
        "# Provenance\n\nUse `evidencelab provenance-index --root . --out provenance/artifacts.json` and keep acquisition records, graph hashes and environment snapshots.\n",
        encoding="utf-8",
    )
    (root / "benchmarks" / "public" / "README.md").write_text(
        "# Public benchmark\n\nOnly cases safe to distribute belong here. Include positive, negative, UNKNOWN, counter-evidence and adversarial dimensions.\n",
        encoding="utf-8",
    )
    (root / "benchmarks" / "hidden" / "README.md").write_text(
        "# Hidden benchmark placeholder\n\nDo not place evaluator-only hidden data in the public research tree. Use `evidencelab hidden-seal` into a separate evaluator-controlled location.\n",
        encoding="utf-8",
    )
    (root / "submissions" / "README.md").write_text(
        "# Evaluation submissions\n\nStore submission manifests and public validation outputs. Do not embed evaluator-only hidden cases or keys.\n",
        encoding="utf-8",
    )
    family_template = {
        "schema_version": SCHEMA_VERSION,
        "family_id": f"{cwe.lower()}-family-001",
        "cwe": cwe,
        "name": "Draft Evidence Family",
        "version": "1.0.0",
        "status": "DRAFT",
        "research_question": "Define a falsifiable graph-observable evidence question for this family.",
        "claim_summary": "Not yet defined.",
        "what_is_proven": "Not yet defined.",
        "what_is_not_proven": "Not yet defined.",
        "provenance": [],
        "coverage": {"required_dimensions": task["expected_evidence_dimensions"]},
        "evidence_contract": {
            "unknown_policy": "unknown",
            "counter_unknown_policy": "block_match",
            "tri_state": True,
            "counter_evidence_binding": "same_witness",
            "minimum_sufficient_witness": True,
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
        "provenance_policy": {
            "derived_facts_require_inputs": True,
            "literature_linkage": True,
            "artifact_hashes": True,
        },
    }
    _write_json(root / "family-template.json", family_template)
    submission = {
        "format": "evidencelab-submission",
        "version": "1.0",
        "schema_version": SCHEMA_VERSION,
        "task": {"cwe": cwe, "language": "C/C++", "substrate": "Joern"},
        "pattern": "evidence/pattern.json",
        "graph_artifacts": [],
        "public_benchmark": "benchmarks/public/benchmark.json",
        "research_provenance": "provenance/",
    }
    pattern = {
        "schema_version": SCHEMA_VERSION,
        "family_id": f"{cwe.lower()}-family-001",
        "pattern_id": f"{cwe.lower()}-family-001",
        "cwe": cwe,
        "name": f"{cwe} Evidence Pattern",
        "version": "1.0.0",
        "language": "C/C++",
        "description": "Draft only: not executable until claims and witnesses are defined.",
        "unknown_policy": "unknown",
        "counter_unknown_policy": "block_match",
        "metadata": {
            "research_question": TASK_TEMPLATE["research_question"],
            "evidence_definition_version": SCHEMA_VERSION,
            "evidence_class": "TEMPLATE",
            "scope_boundary": "Define before publication.",
        },
        "provenance": [
            {
                "kind": "cwe",
                "source": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
            },
            {"kind": "tool", "source": "Joern"},
            {"kind": "methodology", "source": "EvidenceLab research contract"},
        ],
        "coverage": {
            "required_dimensions": task["expected_evidence_dimensions"],
            "minimum_public_cases": 200,
            "minimum_hidden_cases": 160,
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
    _write_json(root / "evidence" / "pattern.json", pattern)
    for part in ("public", "hidden"):
        _write_json(
            root / "benchmarks" / part / "benchmark.json",
            {
                "schema_version": SCHEMA_VERSION,
                "manifest_id": f"{cwe.lower()}-{part}-{SCHEMA_VERSION}-template",
                "format": "evidencelab-benchmark",
                "partition": part,
                "cases": [],
            },
        )
    (root / "experiments" / "experiment-log.jsonl").write_text("", encoding="utf-8")
    (root / "experiments" / "experiment-ledger.jsonl").write_text("", encoding="utf-8")
    (root / "experiments" / "observations.jsonl").write_text("", encoding="utf-8")
    (root / "experiments" / "derivations.jsonl").write_text("", encoding="utf-8")
    _write_json(root / "submission.json", submission)
    _write_json(
        root / "task.provenance.json",
        {
            "generated_by": "EvidenceLab",
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "schema_version": SCHEMA_VERSION,
            "cwe": cwe,
        },
    )
    (root / "limitations.md").write_text(
        "# Limitations and Coverage Gaps\n\nDocument unsupported language constructs, analyzer limitations, precision/recall limits, unresolved UNKNOWN classes, environmental assumptions, and evidence families intentionally not covered.\n",
        encoding="utf-8",
    )
    return root


def append_experiment(root: str | Path, record: dict[str, Any]) -> Path:
    from .experiment import record_experiment

    payload = record_experiment(
        root,
        record.get("hypothesis", ""),
        record.get("tool", ""),
        record.get("command", ""),
        record.get("result", ""),
        record.get("cases", []),
        record.get("parameters", {}),
        record.get("observations", []),
        record.get("notes", ""),
    )
    rootp = Path(root).resolve()
    legacy = rootp / "experiments" / "experiment-log.jsonl"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy_record = dict(record)
    legacy_record.setdefault(
        "experiment_id", record.get("experiment_id") or payload.get("experiment_id")
    )
    legacy.open("a", encoding="utf-8").write(
        json.dumps(legacy_record, ensure_ascii=False, sort_keys=True) + "\n"
    )
    return rootp / "experiments" / "experiment-ledger.jsonl"
