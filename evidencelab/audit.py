from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .spec import Pattern


@dataclass(slots=True)
class AuditFinding:
    id: str
    severity: str
    message: str
    remediation: str = ""

    def to_dict(self):
        return asdict(self)


def audit_pattern(
    pattern: Pattern, profile: dict[str, Any] | None = None
) -> list[AuditFinding]:
    cfg = profile or {}
    out: list[AuditFinding] = []
    req = [c for c in pattern.claims if c.required]
    paths = [
        c
        for c in pattern.claims
        if c.kind
        in {"path", "path_absence", "edge", "relation", "relation_any", "relation_none"}
    ]
    constraints = [
        c
        for c in pattern.claims
        if c.kind
        in {
            "compare",
            "range_compare",
            "same_object",
            "semantic",
            "property",
            "path_absence",
            "node_absence",
        }
    ]

    if len(req) < int(cfg.get("min_required_claims", 8)):
        out.append(
            AuditFinding(
                "A001",
                "ERROR",
                f"only {len(req)} required claims; minimum is {cfg.get('min_required_claims', 8)}",
                "Add independent evidence dimensions.",
            )
        )
    if not paths:
        out.append(
            AuditFinding(
                "A002",
                "ERROR",
                "no graph relationship claim",
                "Require source/sink/object relationships.",
            )
        )
    if not constraints:
        out.append(
            AuditFinding(
                "A003",
                "ERROR",
                "no semantic discriminator",
                "Add quantitative, state, bound, type, or absence constraints.",
            )
        )
    if cfg.get("require_counter_evidence", True) and not pattern.counter_claims:
        out.append(
            AuditFinding(
                "A004",
                "ERROR",
                "no counter-evidence",
                "A research-grade pattern needs evidence that can refute a plausible witness.",
            )
        )
    if cfg.get("require_provenance", True) and len(pattern.provenance) < int(
        cfg.get("min_provenance", 3)
    ):
        out.append(
            AuditFinding(
                "A005",
                "ERROR",
                "insufficient provenance",
                "Record CWE/tool/query/dataset or literature provenance.",
            )
        )
    if len(pattern.concepts) < int(cfg.get("min_concepts", 5)):
        out.append(
            AuditFinding(
                "A006",
                "ERROR",
                f"only {len(pattern.concepts)} concepts; minimum is {cfg.get('min_concepts', 5)}",
                "Prefer semantic concepts over API signatures.",
            )
        )
    if len({c.kind for c in req}) < int(cfg.get("min_required_claim_kinds", 4)):
        out.append(
            AuditFinding(
                "A007",
                "ERROR",
                "insufficient claim diversity",
                "Use node + relation + property/compare evidence.",
            )
        )
    if not pattern.witnesses:
        out.append(
            AuditFinding(
                "A008",
                "ERROR",
                "no coherent witness",
                "Bind causal evidence into one witness.",
            )
        )

    referenced: set[str] = set()
    for w in pattern.witnesses:
        referenced.update(w.claims)
        referenced.update(w.counter_claims)
    unattached = [c.id for c in pattern.claims if c.required and c.id not in referenced]
    if unattached:
        out.append(
            AuditFinding(
                "A009",
                "ERROR",
                "required claims are not attached to witnesses: "
                + ", ".join(unattached),
                "Attach every required claim to at least one witness.",
            )
        )
    unattached_counters = [
        c.id for c in pattern.counter_claims if c.id not in referenced
    ]
    if unattached_counters:
        out.append(
            AuditFinding(
                "A018",
                "ERROR",
                "counter-evidence claims are not attached to witnesses: "
                + ", ".join(unattached_counters),
                "Evaluate counter-evidence against the same coherent witness.",
            )
        )

    if not pattern.unknown_policy:
        out.append(
            AuditFinding(
                "A010",
                "ERROR",
                "unknown policy undefined",
                "Never promote unknown to true.",
            )
        )
    if not pattern.coverage:
        out.append(
            AuditFinding(
                "A011",
                "ERROR",
                "coverage matrix missing",
                "Declare research dimensions and validation obligations.",
            )
        )
    dims = (
        pattern.coverage.get("required_dimensions", [])
        if isinstance(pattern.coverage, dict)
        else []
    )
    if len(set(map(str, dims))) < int(cfg.get("min_coverage_dimensions", 5)):
        out.append(
            AuditFinding(
                "A012",
                "ERROR",
                f"coverage declares only {len(set(map(str, dims)))} dimensions",
                "Add orthogonal evidence dimensions.",
            )
        )
    if cfg.get("require_query_provenance", True) and not any(
        isinstance(p, dict)
        and p.get("kind") in {"query", "tool", "dataset", "literature"}
        for p in pattern.provenance
    ):
        out.append(
            AuditFinding(
                "A013",
                "WARN",
                "provenance lacks explicit query/tool/dataset/literature records",
                "Make experiments reproducible.",
            )
        )

    exact_names = 0
    semantic = 0
    for concept in pattern.concepts.values():
        for selector in concept.selectors:
            exact_names += int(bool(selector.name_any or selector.name_regex))
            semantic += int(
                bool(
                    selector.properties
                    or selector.properties_any
                    or selector.properties_present
                    or selector.type_any
                    or selector.type_all
                )
            )
    if exact_names and semantic <= exact_names and len(constraints) <= 1:
        sev = "ERROR" if cfg.get("signature_only_is_error", False) else "WARN"
        out.append(
            AuditFinding(
                "A014",
                sev,
                "pattern appears signature-driven",
                "Demonstrate structural/data-flow/quantitative discrimination with counter-cases.",
            )
        )
    for concept in pattern.concepts.values():
        for selector in concept.selectors:
            if len(selector.type_all) > 1 or len(selector.canonical_type_all) > 1:
                out.append(
                    AuditFinding(
                        "A019",
                        "ERROR",
                        f"selector in concept {concept.id} uses multiple values in type_all/canonical_type_all",
                        "A node has one semantic type; use *_any for alternatives or separate concepts for conjunctions.",
                    )
                )

    if any(
        c.kind
        in {"path", "path_absence", "edge", "relation", "relation_any", "relation_none"}
        and not (c.edge_types or c.relation)
        for c in pattern.claims
    ):
        sev = "ERROR" if cfg.get("require_relation_edge_types", False) else "WARN"
        out.append(
            AuditFinding(
                "A015",
                sev,
                "relationship claim has no raw edge types or semantic relation",
                "Use relation=DATA_FLOW/REFERENCE/etc. or explicit edge_types.",
            )
        )

    max_hops = int(
        (pattern.path_budget or {}).get("max_hops", cfg.get("max_recommended_hops", 20))
        or 20
    )
    for claim in paths:
        if claim.max_hops > max_hops:
            out.append(
                AuditFinding(
                    "A016",
                    "ERROR",
                    f"path search radius {claim.max_hops} exceeds bounded budget {max_hops}",
                    "Constrain paths with semantic relation and a bounded hop budget.",
                )
            )
    if pattern.counter_unknown_policy == "block_match" and not pattern.coverage.get(
        "unknown_counter_dimension", False
    ):
        out.append(
            AuditFinding(
                "A017",
                "WARN",
                "counter unknowns block matches but coverage does not declare how unknown counter evidence is tested",
                "Add explicit unknown-counter cases.",
            )
        )

    # Current Evidence contract checks are independent of profiles.
    if not pattern.family_id:
        out.append(
            AuditFinding(
                "ELC01",
                "ERROR",
                "current pattern has no family_id",
                "Every evidence definition must belong to one explicit Evidence Family.",
            )
        )
    ec = pattern.evidence_contract
    sc = pattern.semantic_contract
    pp = pattern.provenance_policy
    required = {
        "unknown_policy",
        "counter_unknown_policy",
        "tri_state",
        "counter_evidence_binding",
        "minimum_sufficient_witness",
    }
    missing = sorted(required - set(ec))
    if missing:
        out.append(
            AuditFinding(
                "ELC02",
                "ERROR",
                "evidence_contract missing: " + ", ".join(missing),
                "Declare the formal matching semantics.",
            )
        )
    if ec.get("tri_state") is not True:
        out.append(
            AuditFinding(
                "ELC03",
                "ERROR",
                "tri_state contract is not enabled",
                "UNKNOWN/PARTIAL must remain distinct from NO_MATCH.",
            )
        )
    if (
        sc.get("canonical_graph_required") is not True
        or sc.get("analyzer_independent") is not True
    ):
        out.append(
            AuditFinding(
                "ELC04",
                "ERROR",
                "semantic_contract does not require canonical analyzer-independent semantics",
                "Patterns must consume the canonical semantic layer.",
            )
        )
    if pp.get("derived_facts_require_inputs") is not True:
        out.append(
            AuditFinding(
                "ELC05",
                "ERROR",
                "derived_facts_require_inputs is not enforced",
                "Every definitive derivation must cite source observations/artifacts.",
            )
        )
    if pattern.counter_claims and ec.get("counter_evidence_binding") != "same_witness":
        out.append(
            AuditFinding(
                "ELC06",
                "ERROR",
                "counter evidence is not bound to the same witness",
                "Counter-evidence must use the same source/sink/object binding.",
            )
        )
    if not pattern.relevance_policy:
        out.append(
            AuditFinding(
                "ELC07",
                "ERROR",
                "relevance_policy is missing",
                "Declare minimum-sufficient witness and path relevance rules.",
            )
        )
    if not any(
        isinstance(x, dict) and x.get("kind") == "cwe" for x in pattern.provenance
    ):
        out.append(
            AuditFinding(
                "ELC08",
                "ERROR",
                "CWE mapping provenance is missing",
                "Link the family boundary to the authoritative CWE definition.",
            )
        )
    raw_only = []
    for concept in pattern.concepts.values():
        for selector in concept.selectors:
            has_raw_types = bool(
                getattr(selector, "type_any", None)
                or getattr(selector, "type_all", None)
            )
            has_canonical_types = bool(
                getattr(selector, "canonical_type_any", None)
                or getattr(selector, "canonical_type_all", None)
            )
            if has_raw_types and not has_canonical_types:
                raw_only.append(concept.id)
    if raw_only:
        out.append(
            AuditFinding(
                "ELC09",
                "ERROR",
                "pattern contains raw analyzer type selectors without canonical semantic selectors: "
                + ", ".join(sorted(set(raw_only))),
                "Use canonical_type_any/canonical_type_all and place analyzer-specific aliases behind the canonical adapter.",
            )
        )
    if pp.get("literature_linkage", True) and not any(
        isinstance(x, dict) and x.get("kind") == "literature"
        for x in pattern.provenance
    ):
        out.append(
            AuditFinding(
                "ELC10",
                "ERROR",
                "literature linkage is required for evidence predicates",
                "Map material predicates to papers/standards/dataset documentation.",
            )
        )

    return out
