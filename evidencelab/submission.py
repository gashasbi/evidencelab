from __future__ import annotations
import hashlib, json, re, subprocess, shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .errors import EvidenceLabError, SchemaError
from .parsers import parse_graph
from .profile import load_profile, validate_profile, validate_benchmark_gate
from .audit import audit_pattern
from .matcher import Matcher
from .evaluator import run_manifest, compare_manifests
from .reports import render_text, render_markdown, render_html
from .spec import Pattern

SUBMISSION_FORMAT = "evidencelab-submission"
SUBMISSION_VERSION = "1.0"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def joern_version() -> str | None:
    exe = shutil.which("joern")
    if not exe:
        return None
    try:
        p = subprocess.run(
            [exe], input=":exit\n", text=True, capture_output=True, timeout=20
        )
        m = re.search(r"Version:\s*([^\s]+)", p.stdout + p.stderr)
        return m.group(1) if m else None
    except Exception:
        return None


def _safe(root: Path, rel: str) -> Path:
    c = (root / rel).resolve()
    try:
        c.relative_to(root.resolve())
    except ValueError as e:
        raise SchemaError(f"artifact escapes submission root: {rel}") from e
    return c


@dataclass(slots=True)
class Submission:
    root: Path
    raw: dict[str, Any]

    @classmethod
    def load(cls, root: str | Path) -> "Submission":
        rootp = Path(root).resolve()
        mf = rootp / "submission.json"
        if not rootp.is_dir() or not mf.is_file():
            raise SchemaError(f"invalid submission root: {rootp}")
        raw = json.loads(mf.read_text(encoding="utf-8"))
        if (
            raw.get("format") != SUBMISSION_FORMAT
            or str(raw.get("version")) != SUBMISSION_VERSION
        ):
            raise SchemaError("unsupported submission format/version")
        task = raw.get("task", {})
        cwe = str(task.get("cwe", "")).upper()
        if not re.fullmatch(r"CWE-\d+", cwe):
            raise SchemaError("submission.task.cwe must look like CWE-121")
        if not isinstance(raw.get("pattern"), str) or not raw["pattern"]:
            raise SchemaError("submission.pattern required")
        return cls(rootp, raw)

    @property
    def cwe(self) -> str:
        return str(self.raw["task"]["cwe"]).upper()

    @property
    def pattern_path(self) -> Path:
        return _safe(self.root, self.raw["pattern"])

    def graph_paths(self) -> list[Path]:
        arr = self.raw.get("graph_artifacts", [])
        if not isinstance(arr, list) or not arr:
            raise SchemaError("graph_artifacts must be non-empty")
        return [
            _safe(self.root, str(x["path"]))
            for x in arr
            if isinstance(x, dict) and x.get("path")
        ]

    def public_benchmark(self) -> Path | None:
        x = self.raw.get("public_benchmark")
        return _safe(self.root, str(x)) if x else None

    def validate_files(self) -> list[str]:
        errors = []
        files = [self.pattern_path, *self.graph_paths()]
        if self.public_benchmark():
            files.append(self.public_benchmark())
        for f in files:
            if not f.is_file():
                errors.append(f"missing artifact: {f.relative_to(self.root)}")
        pi = self.raw.get("pattern_integrity")
        if (
            isinstance(pi, dict)
            and pi.get("sha256")
            and self.pattern_path.is_file()
            and sha256_file(self.pattern_path) != str(pi["sha256"])
        ):
            errors.append("pattern sha256 mismatch")
        for item in self.raw.get("graph_artifacts", []):
            if isinstance(item, dict) and item.get("path") and item.get("sha256"):
                p = _safe(self.root, str(item["path"]))
                if p.is_file() and sha256_file(p) != str(item["sha256"]):
                    errors.append(f"graph sha256 mismatch: {item['path']}")
        return errors


def create_submission_manifest(
    root: str | Path,
    cwe: str,
    pattern_rel: str,
    graph_paths: list[str],
    public_benchmark: str | None = None,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    rootp = Path(root).resolve()
    pattern = _safe(rootp, pattern_rel)
    if not pattern.is_file():
        raise EvidenceLabError(f"pattern not found: {pattern_rel}")
    artifacts = []
    for rel in graph_paths:
        p = _safe(rootp, rel)
        if not p.is_file():
            raise EvidenceLabError(f"graph artifact not found: {rel}")
        artifacts.append(
            {"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size}
        )
    raw = {
        "format": SUBMISSION_FORMAT,
        "version": SUBMISSION_VERSION,
        "task": {"cwe": str(cwe).upper(), "language": "C/C++", "substrate": "Joern"},
        "pattern": pattern_rel,
        "pattern_integrity": {"sha256": sha256_file(pattern)},
        "graph_artifacts": artifacts,
        "public_benchmark": public_benchmark,
        "researcher_provenance": provenance or [],
        "toolchain": {"joern_version": joern_version()},
    }
    (rootp / "submission.json").write_text(
        json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return raw


def validate_submission(
    root: str | Path,
    profile_path: str | Path | None = None,
    hidden_benchmark: str | Path | None = None,
    out_dir: str | Path | None = None,
    hide_cases: bool = False,
) -> dict[str, Any]:
    sub = Submission.load(root)
    file_errors = sub.validate_files()
    pattern = Pattern.load(sub.pattern_path)
    profile = load_profile(profile_path) if profile_path else {}
    if pattern.cwe != sub.cwe:
        file_errors.append(
            f"pattern CWE {pattern.cwe} does not match task CWE {sub.cwe}"
        )
    audit = audit_pattern(pattern, profile.get("audit", {})) if profile else []
    pe = validate_profile(pattern, profile) if profile else []
    result = {
        "schema_version": SUBMISSION_VERSION,
        "format": SUBMISSION_FORMAT,
        "submission": sub.raw,
        "file_validation": {
            "status": "PASS" if not file_errors else "FAIL",
            "errors": file_errors,
        },
        "pattern": {
            "id": pattern.pattern_id,
            "cwe": pattern.cwe,
            "version": pattern.version,
        },
        "audit": {
            "status": "PASS"
            if not any(x.severity == "ERROR" for x in audit)
            else "FAIL",
            "findings": [x.to_dict() for x in audit],
        },
        "profile": {"status": "PASS" if not pe else "FAIL", "errors": pe},
        "artifact_results": [],
    }
    if file_errors:
        result["status"] = "FAIL"
    else:
        merged = _merge_graphs(sub.graph_paths())
        m = Matcher(merged).run(pattern)
        result["graph"] = merged.summary()
        result["graph_digest"] = merged.digest()
        result["match"] = m.to_dict()
        result["artifact_results"].append(
            {"status": m.status, "graph_digest": merged.digest()}
        )
        gates = []
        public = sub.public_benchmark()
        if public:
            _, metrics, meta = run_manifest(
                public, pattern, reveal=not hide_cases, partition="public"
            )
            md = metrics.to_dict()
            result["public_evaluation"] = {"metrics": md, "coverage": meta}
            if profile:
                gates.extend(validate_benchmark_gate(md, meta, profile, hidden=False))
        if hidden_benchmark:
            hidden_path = Path(hidden_benchmark).resolve()
            public = sub.public_benchmark()
            if public:
                result["public_hidden_overlap"] = compare_manifests(public, hidden_path)
                if result["public_hidden_overlap"].get("status") != "PASS":
                    gates.append("public/hidden graph-digest overlap detected")
            _, metrics, meta = run_manifest(hidden_path, pattern, reveal=False)
            md = metrics.to_dict()
            result["hidden_evaluation"] = {"metrics": md, "coverage": meta}
            if profile:
                gates.extend(validate_benchmark_gate(md, meta, profile, hidden=True))
        result["research_gates"] = gates
        passed = (
            m.status == "MATCH"
            and not pe
            and result["audit"]["status"] == "PASS"
            and not gates
        )
        result["status"] = (
            "PASS" if passed else ("PARTIAL" if m.status == "PARTIAL" else "FAIL")
        )
    if out_dir:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (d / "report.md").write_text(render_markdown(result), encoding="utf-8")
        (d / "report.html").write_text(render_html(result), encoding="utf-8")
        (d / "report.txt").write_text(render_text(result), encoding="utf-8")
    return result


def _merge_graphs(inputs: list[Path]):
    from .semantics import enrich_graph

    merged = None
    sources = []
    conflicts = []
    saw_full = False
    saw_declared = False
    saw_partial = False
    saw_degraded = False
    for p in inputs:
        g = enrich_graph(parse_graph(p))
        sources.append(
            {
                "path": str(p),
                "digest": g.digest(),
                "format": g.metadata.get("format"),
                "completeness": g.metadata.get("completeness"),
            }
        )
        saw_full |= g.metadata.get("completeness") == "full_export"
        saw_declared |= g.metadata.get("completeness") == "declared"
        saw_partial |= g.metadata.get("completeness") not in {
            None,
            "full_export",
            "declared",
        }
        saw_degraded |= g.metadata.get("parse_health") != "OK"
        if merged is None:
            merged = g
            continue
        for nid, n in g.nodes.items():
            if nid not in merged.nodes:
                merged.add_node(n)
                continue
            cur = merged.nodes[nid]
            if cur.type != n.type and cur.type != "UNKNOWN" and n.type != "UNKNOWN":
                conflicts.append(
                    {"node_id": nid, "existing_type": cur.type, "incoming_type": n.type}
                )
            for k, v in n.properties.items():
                if k not in cur.properties or cur.properties[k] in (None, "", [], {}):
                    cur.properties[k] = v
        existing = {(e.source, e.target, e.type, e.id) for e in merged.edges}
        for e in g.edges:
            key = (e.source, e.target, e.type, e.id)
            if key not in existing:
                merged.add_edge(e)
                existing.add(key)
    if merged is None:
        raise EvidenceLabError("submission has no graph artifacts")
    merged.metadata["completeness"] = (
        "full_export"
        if saw_full
        else ("declared" if saw_declared and not saw_partial else "partial")
    )
    merged.metadata["parse_health"] = (
        "DEGRADED" if saw_degraded else merged.metadata.get("parse_health", "OK")
    )
    merged.metadata["merge_sources"] = sources
    merged.metadata["merge_conflicts"] = conflicts
    return merged
