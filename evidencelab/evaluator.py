from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import json, math, signal, time
from .matcher import Matcher
from .parsers import parse_graph
from .spec import Pattern


EXPECTED = {"MATCH", "NO_MATCH", "UNKNOWN"}


@dataclass(slots=True)
class CaseResult:
    case_id: str
    expected: str
    actual: str
    correct: bool
    partition: str
    tags: list[str]
    graph_digest: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Metrics:
    total: int
    known: int
    tp: int
    fp: int
    tn: int
    fn: int
    expected_unknown: int
    actual_partial: int
    actual_unknown: int
    unknown_correct: int
    unknown_wrong: int
    overclaims: int = 0
    infra_errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        tp, fp, tn, fn = self.tp, self.fp, self.tn, self.fn
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        f1 = (
            (2 * p * r / (p + r)) if p is not None and r is not None and p + r else None
        )
        spec = tn / (tn + fp) if tn + fp else None
        fpr = fp / (fp + tn) if fp + tn else None
        fnr = fn / (fn + tp) if fn + tp else None
        ba = (r + spec) / 2 if r is not None and spec is not None else None
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = ((tp * tn - fp * fn) / denom) if denom else None
        return {
            **asdict(self),
            "precision": p,
            "recall": r,
            "f1": f1,
            "specificity": spec,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "balanced_accuracy": ba,
            "mcc": mcc,
            "unknown_safety_rate": (self.unknown_correct / self.expected_unknown)
            if self.expected_unknown
            else None,
            "overclaim_rate": (self.overclaims / self.expected_unknown)
            if self.expected_unknown
            else None,
            "infra_error_rate": (self.infra_errors / self.total)
            if self.total
            else None,
            "precision_ci95": wilson(tp, tp + fp),
            "recall_ci95": wilson(tp, tp + fn),
            "specificity_ci95": wilson(tn, tn + fp),
            "false_positive_rate_ci95": wilson(fp, fp + tn),
            "false_negative_rate_ci95": wilson(fn, fn + tp),
        }


def wilson(success: int, n: int, z: float = 1.95996398454):
    if n <= 0:
        return None
    phat = success / n
    den = 1 + z * z / n
    ctr = (phat + z * z / (2 * n)) / den
    half = z * math.sqrt((phat * (1 - phat) + z * z / (4 * n)) / n) / den
    return [max(0.0, ctr - half), min(1.0, ctr + half)]


def classify(actual: str, expected: str):
    """Classify a tri-state benchmark without collapsing UNKNOWN into NO_MATCH.

    For an expected UNKNOWN case, only UNKNOWN/PARTIAL preserve the uncertainty
    contract. A confident MATCH or NO_MATCH is an overclaim because the benchmark
    explicitly says that the available information is insufficient to establish a
    definitive outcome.
    """
    if expected == "UNKNOWN":
        uncertainty_preserved = actual in {"UNKNOWN", "PARTIAL"}
        overclaim = int(actual == "MATCH")
        return (
            0,
            0,
            0,
            0,
            1,
            int(actual == "PARTIAL"),
            int(actual == "UNKNOWN"),
            int(uncertainty_preserved),
            int(overclaim),
            overclaim,
        )
    if actual == "MATCH" and expected == "MATCH":
        return (1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    if actual == "MATCH" and expected == "NO_MATCH":
        return (0, 1, 0, 0, 0, 0, 0, 0, 0, 1)
    if actual != "MATCH" and expected == "MATCH":
        return (
            0,
            0,
            0,
            1,
            0,
            int(actual == "PARTIAL"),
            int(actual == "UNKNOWN"),
            0,
            0,
            0,
        )
    return (0, 0, 1, 0, 0, int(actual == "PARTIAL"), int(actual == "UNKNOWN"), 0, 0, 0)


def _trusted_submission_root(manifest: Path) -> Path:
    """Return the smallest trusted project root containing the benchmark manifest.

    Standalone benchmark manifests are rooted at their own directory. Submission
    manifests may intentionally reference sibling assets such as ../graphs/*.json;
    in that case, allow traversal only when it stays inside the nearest directory
    containing submission.json.
    """
    cur = manifest.resolve().parent
    for parent in (cur, *cur.parents):
        if (parent / "submission.json").is_file():
            return parent
    return cur


def _safe_case_path(manifest: Path, rel: str) -> Path:
    """Resolve a graph reference only within declared benchmark asset roots.

    Submission packages may use ``../graphs`` from a nested benchmark directory, but
    arbitrary paths elsewhere in the submission/research tree are not implicitly trusted.
    """
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    base = manifest.resolve().parent
    trusted_root = _trusted_submission_root(manifest)
    rel_path = Path(str(rel))
    if rel_path.is_absolute():
        raise ValueError(f"absolute graph paths are forbidden: {rel}")
    allowed_roots = [base]
    graph_base = raw.get("graph_base")
    if graph_base:
        graph_base_path = Path(str(graph_base))
        if graph_base_path.is_absolute():
            raise ValueError(f"absolute graph_base is forbidden: {graph_base}")
        gb = (base / graph_base_path).resolve()
        try:
            gb.relative_to(base)
        except ValueError as exc:
            raise ValueError(
                f"graph_base escapes benchmark root: {graph_base}"
            ) from exc
        allowed_roots.append(gb)
    if trusted_root != base:
        for name in ("graphs", "graph_artifacts", "benchmarks", "evidence"):
            allowed_roots.append((trusted_root / name).resolve())
    candidates = []
    for root in allowed_roots:
        candidates.append((root / rel_path).resolve())
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for allowed in allowed_roots:
            try:
                candidate.relative_to(allowed)
                return candidate
            except ValueError:
                pass
    raise ValueError(
        f"graph path is outside permitted benchmark asset roots or is missing: {rel}"
    )


def audit_benchmark_manifest(
    manifest_path: str | Path,
    pattern: Pattern,
    strict: bool = True,
    required_dimensions: set[str] | None = None,
) -> dict[str, Any]:
    p = Path(manifest_path).resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    cases = raw.get("cases")
    errors: list[str] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    digest_to_case: dict[str, str] = {}
    digest_labels: dict[str, set[str]] = {}
    tag_counts: dict[str, int] = {}
    dimension_counts: dict[str, int] = {}
    partitions: dict[str, int] = {}
    case_map: dict[str, dict[str, Any]] = {}
    canonical_ready = 0
    canonical_failed: list[dict[str, Any]] = []

    if not isinstance(cases, list) or not cases:
        errors.append("benchmark cases must be a non-empty array")
        return {
            "status": "FAIL",
            "errors": errors,
            "warnings": warnings,
            "case_count": 0,
        }

    for item in cases:
        if not isinstance(item, dict):
            errors.append("benchmark case must be an object")
            continue
        cid = str(item.get("id", ""))
        if not cid:
            errors.append("case missing id")
            continue
        if cid in seen_ids:
            errors.append(f"duplicate case id: {cid}")
        seen_ids.add(cid)
        case_map[cid] = item
        expected = str(item.get("expected", "")).upper()
        if expected not in EXPECTED:
            errors.append(f"{cid}: invalid expected value {expected}")
        rel = item.get("graph")
        if not isinstance(rel, str) or not rel:
            errors.append(f"{cid}: missing graph path")
            continue
        gp = _safe_case_path(p, rel)
        if not gp.exists() or not gp.is_file():
            errors.append(f"{cid}: graph file missing: {rel}")
        tags = [str(t) for t in item.get("tags", [])]
        dimensions = (
            [str(d) for d in item.get("dimensions", [])]
            if isinstance(item.get("dimensions"), list)
            else []
        )
        part = str(item.get("partition", "public"))
        partitions[part] = partitions.get(part, 0) + 1
        for tag in tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

        canonical_case_dims = set(dimensions) | set(tags)
        for dim in canonical_case_dims:
            dimension_counts[dim] = dimension_counts.get(dim, 0) + 1
        if gp.exists() and gp.is_file():
            try:
                graph = parse_graph(gp)
            except Exception as exc:
                errors.append(f"{cid}: graph parse failed: {type(exc).__name__}: {exc}")
                canonical_failed.append(
                    {"id": cid, "errors": [f"graph parse failed: {exc}"]}
                )
                continue
            digest = graph.digest()
            try:
                from .canonical import canonicalize_graph, canonical_validation

                cg = canonicalize_graph(graph)
                cv = canonical_validation(cg)
                if cv.get("status") == "PASS":
                    canonical_ready += 1
                else:
                    canonical_failed.append({"id": cid, "errors": cv.get("errors", [])})
            except Exception as exc:
                canonical_failed.append(
                    {"id": cid, "errors": [f"canonicalization failed: {exc}"]}
                )
            prior = digest_to_case.get(digest)
            if prior and prior != cid:
                msg = f"duplicate graph content: {cid} and {prior}"
                (
                    errors
                    if strict and raw.get("allow_duplicate_graphs", False) is not True
                    else warnings
                ).append(msg)
            else:
                digest_to_case[digest] = cid
            digest_labels.setdefault(digest, set()).add(expected)
        if "mutation_of" in item:
            parent = str(item.get("mutation_of", ""))
            if not parent or parent == cid:
                errors.append(f"{cid}: mutation_of must reference another case")
            if "changed_dimension" not in item or not str(
                item.get("changed_dimension", "")
            ):
                errors.append(f"{cid}: mutation case requires changed_dimension")

    for cid, item in case_map.items():
        parent = item.get("mutation_of")
        if parent and str(parent) not in case_map:
            errors.append(f"{cid}: mutation_of references unknown case {parent}")
    for cid in case_map:
        seen_chain = set()
        cur = cid
        while cur in case_map and case_map[cur].get("mutation_of"):
            if cur in seen_chain:
                errors.append(f"mutation cycle detected at {cid}")
                break
            seen_chain.add(cur)
            cur = str(case_map[cur]["mutation_of"])

    for cid, item in case_map.items():
        parent = item.get("mutation_of")
        relation = item.get("expected_relation")
        if not parent or relation is None or str(parent) not in case_map:
            continue
        parent_expected = str(case_map[str(parent)].get("expected", "UNKNOWN")).upper()
        child_expected = str(item.get("expected", "UNKNOWN")).upper()
        observed_relation = (
            "indeterminate"
            if "UNKNOWN" in {parent_expected, child_expected}
            else ("flip" if parent_expected != child_expected else "same")
        )
        if str(relation) != observed_relation:
            errors.append(
                f"{cid}: expected_relation={relation} disagrees with parent/child labels ({observed_relation})"
            )

    for digest, labels in digest_labels.items():
        if len(labels) > 1:
            errors.append(
                f"graph digest has conflicting expected labels: {sorted(labels)}"
            )

    required = (
        set(map(str, required_dimensions))
        if required_dimensions is not None
        else set(map(str, pattern.coverage.get("required_dimensions", [])))
    )
    canonical_aliases = {
        "guard_dominance": "control_conditions",
        "incomplete_analysis": "analysis_completeness",
        "mutate_extent_only": "mutation",
        "mutate_object_only": "mutation",
        "mutate_analysis_completeness": "mutation",
    }
    canonical_dimensions = dict(dimension_counts)
    for key, value in list(dimension_counts.items()):
        target = canonical_aliases.get(key)
        if target:
            canonical_dimensions[target] = canonical_dimensions.get(target, 0) + value
    missing = [x for x in sorted(required) if canonical_dimensions.get(x, 0) == 0]
    if missing:
        errors.append("required benchmark dimensions missing: " + ", ".join(missing))

    minimum_public = int(pattern.coverage.get("minimum_public_cases", 0) or 0)
    if partitions.get("public", 0) < minimum_public:
        warnings.append(
            f"public case count below pattern advisory minimum: {partitions.get('public', 0)} < {minimum_public}"
        )

    real_world_cases = sum(
        1
        for x in cases
        if isinstance(x, dict)
        and (
            "real_world" in {str(t) for t in x.get("tags", [])}
            or "real_world" in {str(d) for d in x.get("dimensions", [])}
        )
    )
    if canonical_failed:
        errors.append(
            f"canonical graph preparation failed for {len(canonical_failed)} cases"
        )
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "case_count": len(cases),
        "unique_graphs": len(digest_to_case),
        "tag_counts": tag_counts,
        "dimension_counts": canonical_dimensions,
        "partitions": partitions,
        "mutation_cases": sum(
            1 for x in cases if isinstance(x, dict) and x.get("mutation_of")
        ),
        "real_world_cases": real_world_cases,
        "source_diversity": len(
            {
                str((x.get("dataset") or {}).get("name"))
                for x in cases
                if isinstance(x, dict) and (x.get("dataset") or {}).get("name")
            }
        ),
        "repository_diversity": len(
            {
                str(
                    (x.get("dataset") or {}).get("repository")
                    or (x.get("dataset") or {}).get("repo")
                )
                for x in cases
                if isinstance(x, dict)
                and (
                    (x.get("dataset") or {}).get("repository")
                    or (x.get("dataset") or {}).get("repo")
                )
            }
        ),
        "project_diversity": len(
            {
                str((x.get("dataset") or {}).get("project"))
                for x in cases
                if isinstance(x, dict) and (x.get("dataset") or {}).get("project")
            }
        ),
        "cve_diversity": len(
            {
                str(cve)
                for x in cases
                if isinstance(x, dict)
                for cve in (
                    (x.get("dataset") or {}).get("cve")
                    if isinstance((x.get("dataset") or {}).get("cve"), list)
                    else [((x.get("dataset") or {}).get("cve"))]
                )
                if cve
            }
        ),
        "split_metadata": raw.get("split", {}),
        "canonical_graph": {
            "status": "PASS" if not canonical_failed else "FAIL",
            "ready_cases": canonical_ready,
            "failed_cases": len(canonical_failed),
            "failures": canonical_failed[:100],
            "required_reference": "EvidenceLab-Canonical-Semantic-1",
        },
    }


def compare_manifests(
    public_path: str | Path, hidden_path: str | Path
) -> dict[str, Any]:
    """Detect graph, normalized-source, and case-id overlap across public/hidden partitions."""

    def read(path: Path):
        raw = json.loads(path.read_text(encoding="utf-8"))
        out = {}
        for item in raw.get("cases", []):
            gp = _safe_case_path(path, str(item["graph"]))
            normalized = item.get("normalized_source_hash") or (
                item.get("source_metadata") or {}
            ).get("normalized_source_hash")
            source_hash = (
                item.get("source_sha256")
                or item.get("source_content_sha256")
                or (item.get("source_metadata") or {}).get("sha256")
            )
            if gp.is_file():
                out[str(item["id"])] = {
                    "graph_digest": parse_graph(gp).digest(),
                    "expected": str(item.get("expected", "UNKNOWN")),
                    "normalized_source_hash": str(normalized) if normalized else None,
                    "source_sha256": str(source_hash) if source_hash else None,
                }
        return out

    pub_path = Path(public_path).resolve()
    hid_path = Path(hidden_path).resolve()
    pub = read(pub_path)
    hid = read(hid_path)
    p_by_digest = {v["graph_digest"]: cid for cid, v in pub.items()}
    p_by_norm = {
        v["normalized_source_hash"]: cid
        for cid, v in pub.items()
        if v.get("normalized_source_hash")
    }
    p_by_sha = {
        v["source_sha256"]: cid for cid, v in pub.items() if v.get("source_sha256")
    }
    graph_overlaps = [
        {
            "public_case": p_by_digest[v["graph_digest"]],
            "hidden_case": cid,
            "graph_digest": v["graph_digest"],
        }
        for cid, v in hid.items()
        if v["graph_digest"] in p_by_digest
    ]
    normalized_overlaps = [
        {
            "public_case": p_by_norm[v["normalized_source_hash"]],
            "hidden_case": cid,
            "normalized_source_hash": v["normalized_source_hash"],
        }
        for cid, v in hid.items()
        if v.get("normalized_source_hash") and v["normalized_source_hash"] in p_by_norm
    ]
    source_overlaps = [
        {
            "public_case": p_by_sha[v["source_sha256"]],
            "hidden_case": cid,
            "source_sha256": v["source_sha256"],
        }
        for cid, v in hid.items()
        if v.get("source_sha256") and v["source_sha256"] in p_by_sha
    ]
    id_overlaps = sorted(set(pub).intersection(hid))
    conflicts = []
    for cid in sorted(set(pub).intersection(hid)):
        if pub[cid]["expected"] != hid[cid]["expected"]:
            conflicts.append(cid)
    errors = (
        graph_overlaps
        + normalized_overlaps
        + source_overlaps
        + [{"case_id": c} for c in conflicts]
    )
    return {
        "status": "FAIL" if errors else "PASS",
        "overlaps": graph_overlaps,
        "normalized_source_overlaps": normalized_overlaps,
        "source_sha256_overlaps": source_overlaps,
        "case_id_overlaps": id_overlaps,
        "label_conflicts": conflicts,
        "public_cases": len(pub),
        "hidden_cases": len(hid),
    }


class CaseResourceLimit(RuntimeError):
    pass


class _CaseAlarm:
    def __init__(self, seconds: int | float | None):
        self.seconds = float(seconds or 0)
        self.previous = None

    def __enter__(self):
        if self.seconds > 0 and hasattr(signal, "SIGALRM"):
            self.previous = signal.getsignal(signal.SIGALRM)

            def handler(_signum, _frame):
                raise CaseResourceLimit(
                    f"case exceeded resource time limit: {self.seconds}s"
                )

            signal.signal(signal.SIGALRM, handler)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.seconds > 0 and hasattr(signal, "SIGALRM"):
            signal.setitimer(signal.ITIMER_REAL, 0)
            if self.previous is not None:
                signal.signal(signal.SIGALRM, self.previous)
        return False


def run_manifest(
    manifest_path: str | Path,
    pattern: Pattern,
    reveal: bool = True,
    partition: str | None = None,
    case_timeout_seconds: int | float | None = None,
    required_dimensions: set[str] | None = None,
    require_analyzer_attestation: bool = False,
):
    mp = Path(manifest_path).resolve()
    raw = json.loads(mp.read_text(encoding="utf-8"))
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark manifest needs non-empty cases")
    out: list[CaseResult] = []
    tp = fp = tn = fn = unk = partial = actual_unknown = unk_correct = unk_wrong = (
        overclaims
    ) = infra_errors = 0
    seen: set[str] = set()
    by_tag: dict[str, dict[str, Any]] = {}
    by_dimension: dict[str, dict[str, Any]] = {}
    by_partition: dict[str, int] = {}
    digests: dict[str, str] = {}
    warnings: list[str] = []
    for item in cases:
        cid = str(item["id"])
        part = str(item.get("partition", "public"))
        if partition and part != partition:
            continue
        if cid in seen:
            raise ValueError(f"duplicate case id: {cid}")
        seen.add(cid)
        expected = str(item["expected"]).upper()
        if expected not in EXPECTED:
            raise ValueError(f"{cid}: invalid expected")
        started = time.perf_counter()
        try:
            with _CaseAlarm(case_timeout_seconds):
                g = parse_graph(_safe_case_path(mp, str(item["graph"])))
                d = g.digest()
                if d in digests and digests[d] != cid:
                    warnings.append(f"duplicate graph digest: {cid} and {digests[d]}")
                digests[d] = cid
                match = Matcher(
                    g, require_analyzer_attestation=require_analyzer_attestation
                ).run(pattern)
                actual = match.status
        except CaseResourceLimit as exc:
            infra_errors += 1
            actual = "INFRA_ERROR"
            d = ""
            match = None
            warnings.append(f"{cid}: {exc}")
        except Exception as exc:
            infra_errors += 1
            actual = "INFRA_ERROR"
            d = ""
            match = None
            warnings.append(f"{cid}: infrastructure error: {type(exc).__name__}: {exc}")
        if actual == "INFRA_ERROR":
            a = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        else:
            a = classify(actual, expected)
            tp += a[0]
            fp += a[1]
            tn += a[2]
            fn += a[3]
            unk += a[4]
            partial += a[5]
            actual_unknown += a[6]
            unk_correct += a[7]
            unk_wrong += a[8]
            overclaims += a[9]
        tags = [str(x) for x in item.get("tags", [])]
        correct = (expected == "UNKNOWN" and actual in {"UNKNOWN", "PARTIAL"}) or (
            expected != "UNKNOWN" and actual == expected
        )
        for tag in tags:
            b = by_tag.setdefault(
                tag,
                {
                    "total": 0,
                    "known": 0,
                    "correct": 0,
                    "tp": 0,
                    "fp": 0,
                    "tn": 0,
                    "fn": 0,
                },
            )
            b["total"] += 1
            b["correct"] += int(correct)
            if expected != "UNKNOWN":
                b["known"] += 1
                b["tp"] += a[0]
                b["fp"] += a[1]
                b["tn"] += a[2]
                b["fn"] += a[3]
        for dim in set(str(x) for x in item.get("dimensions", []) or []):
            b = by_dimension.setdefault(
                dim, {"total": 0, "known": 0, "correct": 0, "infra_errors": 0}
            )
            b["total"] += 1
            b["correct"] += int(correct)
            b["infra_errors"] += int(actual == "INFRA_ERROR")
            if expected != "UNKNOWN":
                b["known"] += 1
        by_partition[part] = by_partition.get(part, 0) + 1
        if match is None:
            detail = {
                "status": actual,
                "resource_status": "INFRA_ERROR",
                "elapsed_seconds": round(time.perf_counter() - started, 6),
            }
            correct = False
        else:
            detail = (
                match.to_dict()
                if reveal
                else {
                    "status": actual,
                    "evidence_trace": match.evidence_trace,
                    "warnings": match.warnings,
                }
            )
            detail["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        out.append(CaseResult(cid, expected, actual, correct, part, tags, d, detail))
    metrics = Metrics(
        len(out),
        tp + fp + tn + fn,
        tp,
        fp,
        tn,
        fn,
        unk,
        partial,
        actual_unknown,
        unk_correct,
        unk_wrong,
        overclaims,
        infra_errors,
    )
    audit_meta = audit_benchmark_manifest(
        mp, pattern, strict=False, required_dimensions=required_dimensions
    )
    return (
        out,
        metrics,
        {
            "manifest_id": raw.get("manifest_id", mp.stem),
            "coverage_by_tag": by_tag,
            "coverage_by_dimension": by_dimension,
            "partitions": by_partition,
            "warnings": warnings,
            "overclaims": overclaims,
            "infra_errors": infra_errors,
            "benchmark_audit": audit_meta,
            "dimension_counts": audit_meta.get("dimension_counts", {}),
        },
    )
