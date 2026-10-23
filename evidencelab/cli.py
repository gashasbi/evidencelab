from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__, SCHEMA_VERSION
from .audit import audit_pattern
from .capture import capture_joern, validate_capture_manifest_for_merge
from .cwe import sync_catalog, load_catalog, get
from .doctor import run as doctor_run
from .errors import EvidenceLabError
from .evaluator import run_manifest, audit_benchmark_manifest
from .matcher import Matcher
from .parsers import parse_graph
from .profile import load_profile, validate_profile, validate_benchmark_gate
from .reports import render_text, render_markdown, render_html
from .semantics import enrich_graph
from .spec import Pattern
from .submission import validate_submission, create_submission_manifest
from .research_check import run_research_check
from .research_package import audit_research_package
from .project import init_research_project, append_experiment
from .research_records import (
    record_observation,
    record_derivation,
    audit_research_ledgers,
)
from .family import init_evidence_family
from .corpus import source_inventory, tag_matrix, split_manifest
from .tef import load_document, validate_tef, to_evidencelab_notes
from .sarif import write_sarif
from .datasets import (
    import_juliet,
    import_sard_table,
    import_primevul_jsonl,
    import_secvuleval_jsonl,
    import_diversevul_jsonl,
    merge_dataset_manifests,
)
from .splits import split_benchmark, chronological_split, audit_split_directory
from .leakage import audit_source_files, audit_benchmark_lineage
from .provenance import build_provenance_manifest, verify_artifact_manifest
from .git_pairs import build_commit_pair
from .sarif_ingest import sarif_to_graph
from .performance import profile_pattern
from .witness_validator import (
    validate_report,
    validate_benchmark_matches,
    replay_stored_report,
)
from .corpus_runner import capture_dataset
from .mutations import mutate_file
from .benchmark_build import compose_benchmarks, benchmark_plan
from .hidden import seal_hidden_benchmark, verify_hidden_bundle
from .scanner import scan_source
from .research_evaluation import (
    run_research_evaluation,
    evaluate_benchmark,
    replay_stored_directory,
)
from .research_pipeline import build_external_research_corpus, research_readiness
from .contract import (
    write_research_inventory,
    verify_research_inventory,
    audit_no_placeholders,
    build_coverage_matrix,
    bundle_research_package,
)
from .acquire import fetch as fetch_url, fetch_registry_dataset
from .migration import migrate_pattern_to_current
from .evidence_dsl import validate_els, compile_els_file, write_compiled
from .dataset_model import validate_model, write_materialized, materialize


def validate_json_schema(instance_path: str, schema_path: str) -> dict:
    try:
        import jsonschema
    except ImportError as exc:
        raise EvidenceLabError(
            "jsonschema is required for schema-check; install EvidenceLab or the dev dependencies"
        ) from exc
    instance = json.loads(Path(instance_path).read_text(encoding="utf-8"))
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(instance)
    except jsonschema.ValidationError as exc:
        return {
            "status": "FAIL",
            "error": exc.message,
            "path": list(exc.absolute_path),
            "schema_path": list(exc.absolute_schema_path),
        }
    return {
        "status": "PASS",
        "input": str(Path(instance_path).resolve()),
        "schema": str(Path(schema_path).resolve()),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evidencelab",
        description="Research-grade, evidence-first vulnerability research and graph-evidence evaluation framework",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    s = p.add_subparsers(dest="cmd", required=True)

    a = s.add_parser("audit")
    a.add_argument("--pattern", required=True)
    a.add_argument("--profile")
    a.add_argument("--json", action="store_true")
    i = s.add_parser("inspect")
    i.add_argument("--graph", required=True)
    i.add_argument("--detailed", action="store_true")
    i.add_argument("--strict", action="store_true")
    n = s.add_parser("normalize")
    n.add_argument("--graph", required=True)
    n.add_argument("--out", required=True)
    n.add_argument("--pretty", action="store_true")
    m = s.add_parser("merge")
    m.add_argument("--graph", action="append", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--pretty", action="store_true")
    m.add_argument(
        "--manifest", help="capture manifest used to verify analyzer attestation"
    )
    v = s.add_parser("validate")
    v.add_argument("--graph")
    v.add_argument("--pattern", required=True)
    v.add_argument("--benchmark")
    v.add_argument("--profile")
    v.add_argument("--hidden", action="store_true")
    v.add_argument("--hide-cases", action="store_true")
    v.add_argument(
        "--format", choices=["text", "json", "md", "html", "all"], default="text"
    )
    v.add_argument("--out", default="validation-report.json")
    v.add_argument("--report-dir", default="validation-report")
    b = s.add_parser("benchmark-audit")
    b.add_argument("--benchmark", required=True)
    b.add_argument("--pattern", required=True)
    b.add_argument("--json", action="store_true")
    bs = s.add_parser("benchmark-split")
    bs.add_argument("--manifest", required=True)
    bs.add_argument("--public-out", required=True)
    bs.add_argument("--hidden-out", required=True)
    bs.add_argument("--hidden-fraction", type=float, default=0.2)
    bs.add_argument("--seed", default="evidencelab")
    bc = s.add_parser("benchmark-compose")
    bc.add_argument("--input", action="append", required=True)
    bc.add_argument("--out", required=True)
    bc.add_argument("--no-copy-graphs", action="store_true")
    bc.add_argument("--allow-conflicting-labels", action="store_true")
    bc.add_argument("--drop-unknown", action="store_true")
    bp = s.add_parser("benchmark-plan")
    bp.add_argument("--benchmark", required=True)
    bp.add_argument("--profile", required=True)
    bp.add_argument("--out")
    hs = s.add_parser("hidden-seal")
    hs.add_argument("--benchmark", required=True)
    hs.add_argument("--out", required=True)
    hs.add_argument("--key-env")
    hs.add_argument("--require-hmac", action="store_true")
    hs.add_argument(
        "--origin",
        choices=["external-evaluator", "source-derived-demo"],
        default="external-evaluator",
    )
    hv = s.add_parser("hidden-verify")
    hv.add_argument("--bundle", required=True)
    hv.add_argument("--key-env")
    hv.add_argument("--require-hmac", action="store_true")
    hv.add_argument("--require-external-origin", action="store_true")
    sc = s.add_parser(
        "schema-check", help="validate a JSON artifact against a JSON Schema"
    )
    sc.add_argument("--input", required=True)
    sc.add_argument("--schema", required=True)
    mig = s.add_parser(
        "migrate-pattern",
        help="normalize an imported Evidence Pattern to the current contract; researcher review is required",
    )
    mig.add_argument("--pattern", required=True)
    mig.add_argument("--out", required=True)
    mig.add_argument("--family-id")
    q = s.add_parser("benchmark-quality")
    q.add_argument("--benchmark", required=True)
    q.add_argument("--min-cases", type=int, default=120)
    q.add_argument("--min-positive", type=int, default=40)
    q.add_argument("--min-negative", type=int, default=40)
    q.add_argument("--min-unknown", type=int, default=20)
    q.add_argument("--profile")
    q.add_argument("--out")

    init = s.add_parser("init", help="create a complete researcher workspace")
    init.add_argument("--cwe", required=True)
    init.add_argument("--out", required=True)
    init.add_argument("--overwrite", action="store_true")
    cap = s.add_parser("capture")
    cap.add_argument("--source", required=True)
    cap.add_argument("--out", required=True)
    cap.add_argument("--no-graphson", action="store_true")
    cap.add_argument("--no-dataflow", action="store_true")
    cap.add_argument("--dataflow-timeout", type=int, default=300)
    cap.add_argument("--dataflow-slice-depth", type=int, default=8)
    cap.add_argument("--dataflow-file-filter")
    cap.add_argument("--dataflow-method-name-filter")
    cap.add_argument("--best-effort-dataflow", action="store_true")
    ss = s.add_parser(
        "scan", help="run one or more Evidence Patterns on a real source using Joern"
    )
    ss.add_argument("--source", required=True)
    ss.add_argument("--pattern", action="append")
    ss.add_argument("--family-root")
    ss.add_argument("--out", required=True)
    ss.add_argument("--dataflow-timeout", type=int, default=300)
    ss.add_argument("--dataflow-slice-depth", type=int, default=8)
    ss.add_argument("--no-capture-retention", action="store_true")
    d = s.add_parser("doctor")
    d.add_argument("--joern", action="store_true")

    sub = s.add_parser("validate-submission")
    sub.add_argument("--submission", required=True)
    sub.add_argument("--profile")
    sub.add_argument("--hidden-benchmark")
    sub.add_argument("--hide-cases", action="store_true")
    sub.add_argument("--report-dir", default="validation-report")
    make = s.add_parser("make-submission")
    make.add_argument("--root", required=True)
    make.add_argument("--cwe", required=True)
    make.add_argument("--pattern", required=True)
    make.add_argument("--graph", action="append", required=True)
    make.add_argument("--public-benchmark")
    make.add_argument("--out")

    rc = s.add_parser("research-check")
    rc.add_argument("--root", required=True)
    rc.add_argument("--profile")
    rc.add_argument("--hidden-root")
    rc.add_argument(
        "--hidden-key-env",
        help="environment variable containing an optional HMAC verification key for the hidden bundle",
    )
    rc.add_argument("--enforce-gates", action="store_true")
    rc.add_argument("--require-hidden", action="store_true")
    rc.add_argument(
        "--summary",
        action="store_true",
        help="print a compact research status instead of the full report",
    )
    rc.add_argument("--out")
    rr = s.add_parser(
        "research-readiness",
        help="produce an actionable research-grade readiness report",
    )
    rr.add_argument("--root", required=True)
    rr.add_argument("--profile", required=True)
    rr.add_argument("--hidden-root")
    rr.add_argument("--out")
    rbld = s.add_parser(
        "research-build",
        help="capture/compose external dataset manifests into one auditable corpus",
    )
    rbld.add_argument("--input", action="append", required=True)
    rbld.add_argument("--out-dir", required=True)
    rbld.add_argument("--cwe")
    rbld.add_argument("--profile")
    rbld.add_argument("--timeout", type=int, default=600)
    rbld.add_argument("--limit", type=int)
    rbld.add_argument("--no-capture", action="store_true")
    rbld.add_argument("--no-split", action="store_true")
    dvld = s.add_parser(
        "dataset-validate",
        help="validate a dataset manifest for provenance, identity and source integrity",
    )
    dvld.add_argument("--input", required=True)
    dvld.add_argument("--require-label-provenance", action="store_true")
    dvld.add_argument("--require-case-identity", action="store_true")
    dvld.add_argument("--require-source-hash", action="store_true")
    reval = s.add_parser(
        "research-evaluate",
        help="run and persist a complete reproducible research evaluation",
    )
    reval.add_argument("--root", required=True)
    reval.add_argument("--profile", required=True)
    reval.add_argument("--hidden-root")
    reval.add_argument("--out")
    reval.add_argument("--enforce-gates", action="store_true")
    reval.add_argument("--summary", action="store_true")
    reval.add_argument("--hidden-key-env")
    evalp = s.add_parser(
        "evaluate-benchmark",
        help="run one benchmark and persist per-case matcher artifacts",
    )
    evalp.add_argument("--benchmark", required=True)
    evalp.add_argument("--pattern", required=True)
    evalp.add_argument("--out", required=True)
    evalp.add_argument("--partition")
    evalp.add_argument("--no-replay", action="store_true")
    evalp.add_argument("--performance-repeats", type=int, default=1)
    wr = s.add_parser(
        "witness-replay",
        help="independently replay a stored fixed-binding witness without candidate search",
    )
    wr.add_argument("--report", required=True)
    wr.add_argument("--graph", required=True)
    wr.add_argument("--pattern", required=True)
    wrb = s.add_parser(
        "witness-replay-batch",
        help="replay all stored evaluation case reports without rerunning the matcher",
    )
    wrb.add_argument("--results-dir", required=True)
    wrb.add_argument("--pattern", required=True)
    ri = s.add_parser("research-init")
    ri.add_argument("--cwe", required=True)
    ri.add_argument("--out", required=True)
    ri.add_argument("--overwrite", action="store_true")
    fi = s.add_parser(
        "family-init", help="create a new Evidence Family inside a research workspace"
    )
    fi.add_argument("--research-root", required=True)
    fi.add_argument("--family-id", required=True)
    fi.add_argument("--name")
    fi.add_argument("--research-question")
    fi.add_argument("--version", default="0.1.0")
    fi.add_argument("--overwrite", action="store_true")
    rr = s.add_parser("research-audit")
    rr.add_argument("--root", required=True)
    rr.add_argument("--require-hidden", action="store_true")
    rr.add_argument("--out")
    rexp = s.add_parser("research-record")
    rexp.add_argument("--root", required=True)
    rexp.add_argument("--experiment-id")
    rexp.add_argument("--hypothesis", required=True)
    rexp.add_argument("--tool", required=True)
    rexp.add_argument("--command", required=True)
    rexp.add_argument("--result", required=True)
    rexp.add_argument("--case", action="append", default=[])
    rexp.add_argument("--notes", default="")
    obs = s.add_parser(
        "observation-record",
        help="append a provenance-linked raw analyzer observation to the research ledger",
    )
    obs.add_argument("--root", required=True)
    obs.add_argument("--hypothesis-id")
    obs.add_argument("--analyzer", required=True)
    obs.add_argument("--query")
    obs.add_argument("--artifact")
    obs.add_argument("--statement")
    obs.add_argument("--state", default="OBSERVED")
    obs.add_argument("--location", action="append", default=[])
    obs.add_argument("--raw-digest")
    obs.add_argument("--notes", default="")
    der = s.add_parser(
        "derivation-record",
        help="append a provenance-linked semantic derivation to the research ledger",
    )
    der.add_argument("--root", required=True)
    der.add_argument("--hypothesis-id")
    der.add_argument("--method", required=True)
    der.add_argument("--input", action="append", dest="inputs", default=[])
    der.add_argument(
        "--output", required=True, help="JSON object representing the derived fact"
    )
    der.add_argument("--assumption", action="append", default=[])
    der.add_argument("--state", default="PROVEN")
    der.add_argument("--evidence-definition")
    der.add_argument(
        "--replay", help="JSON object describing how to replay the derivation"
    )
    der.add_argument("--notes", default="")
    rs = s.add_parser(
        "research-status",
        help="compact status of research package, ledgers, families and benchmarks",
    )
    rs.add_argument("--root", required=True)
    rs.add_argument("--profile")
    rs.add_argument("--hidden-root")
    ci = s.add_parser("corpus-inventory")
    ci.add_argument("--root", required=True)
    ci.add_argument("--out", required=True)
    tm = s.add_parser("corpus-tags")
    tm.add_argument("--manifest", required=True)
    tm.add_argument("--out")
    cm = s.add_parser(
        "coverage-matrix",
        help="build a machine-readable evidence-dimension/label coverage matrix",
    )
    cm.add_argument("--manifest", required=True)
    cm.add_argument("--out")
    li = s.add_parser("leakage-audit")
    li.add_argument("--source", action="append", required=True)
    li.add_argument("--threshold", type=float, default=0.92)
    li.add_argument("--max-comparisons", type=int, default=250000)
    li.add_argument("--out")
    lm = s.add_parser("leakage-audit-manifest")
    lm.add_argument("--benchmark", required=True)
    lm.add_argument("--threshold", type=float, default=0.92)
    lm.add_argument("--max-comparisons", type=int, default=250000)
    lm.add_argument("--out")
    lb = s.add_parser("lineage-audit")
    lb.add_argument("--benchmark", required=True)
    lb.add_argument("--out")
    sp = s.add_parser("split")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--out-dir", required=True)
    sp.add_argument(
        "--strategy",
        choices=["repository", "project", "cve", "mutation"],
        default="repository",
    )
    sp.add_argument("--train", type=float, default=0.6)
    sp.add_argument("--validation", type=float, default=0.2)
    sp.add_argument("--test", type=float, default=0.2)
    sp.add_argument("--seed", default="evidencelab-1.0.0")
    sp.add_argument("--allow-missing-group", action="store_true")
    tsp = s.add_parser("split-chronological")
    tsp.add_argument("--manifest", required=True)
    tsp.add_argument("--out-dir", required=True)
    tsp.add_argument("--train", type=float, default=0.6)
    tsp.add_argument("--validation", type=float, default=0.2)
    tsp.add_argument("--allow-missing-date", action="store_true")
    spa = s.add_parser(
        "split-audit",
        help="audit train/validation/test manifests for cross-partition leakage",
    )
    spa.add_argument("--dir", required=True)
    spa.add_argument("--strategy")
    ri2 = s.add_parser(
        "research-inventory", help="hash a research workspace for reproducibility"
    )
    ri2.add_argument("--root", required=True)
    ri2.add_argument("--out", required=True)
    ri2.add_argument("--include-hidden", action="store_true")
    ri2.add_argument("--include-external-data", action="store_true")
    rv2 = s.add_parser(
        "research-inventory-verify", help="verify a stored research inventory"
    )
    rv2.add_argument("--manifest", required=True)
    ph = s.add_parser(
        "placeholder-audit", help="detect unfinished executable pattern templates"
    )
    ph.add_argument("--root", required=True)
    ph.add_argument("--allow-scaffold", action="store_true")
    rb = s.add_parser("research-bundle", help="create a reproducibility tar.gz bundle")
    rb.add_argument("--root", required=True)
    rb.add_argument("--out", required=True)
    rb.add_argument("--include-hidden", action="store_true")
    rb.add_argument("--include-external-data", action="store_true")

    dj = s.add_parser("dataset-import-juliet")
    dj.add_argument("--root", required=True)
    dj.add_argument("--out", required=True)
    dj.add_argument("--cwe")
    dj.add_argument("--partition", default="public")
    dj.add_argument("--copy-source", action="store_true")
    dj.add_argument("--copy-root")
    dj.add_argument("--label-mode", choices=["unknown", "heuristic"], default="unknown")
    ds = s.add_parser("dataset-import-sard")
    ds.add_argument("--input", required=True)
    ds.add_argument("--out", required=True)
    ds.add_argument("--cwe")
    ds.add_argument("--source-root")
    dp = s.add_parser("dataset-import-primevul")
    dp.add_argument("--input", required=True)
    dp.add_argument("--out", required=True)
    dp.add_argument("--source-root", required=True)
    dp.add_argument("--cwe")
    dv = s.add_parser("dataset-import-secvuleval")
    dv.add_argument("--input", required=True)
    dv.add_argument("--out", required=True)
    dv.add_argument("--source-root", required=True)
    dv.add_argument("--cwe")
    ddv = s.add_parser("dataset-import-diversevul")
    ddv.add_argument("--input", required=True)
    ddv.add_argument("--out", required=True)
    ddv.add_argument("--source-root", required=True)
    ddv.add_argument("--cwe")
    dm = s.add_parser("dataset-merge")
    dm.add_argument("--input", action="append", required=True)
    dm.add_argument("--out", required=True)
    dai = s.add_parser("dataset-index-archive")
    dai.add_argument("--archive", required=True)
    dai.add_argument("--out", required=True)
    dr = s.add_parser("dataset-registry")
    dr.add_argument("--file", default="datasets/registry.json")
    df = s.add_parser("dataset-fetch")
    df.add_argument("--id", required=True)
    df.add_argument(
        "--artifact",
        help="registry artifact id when a dataset publishes multiple files",
    )
    df.add_argument("--registry", default="datasets/registry.json")
    df.add_argument("--out", required=True)
    df.add_argument("--timeout", type=int, default=300)
    df.add_argument("--max-bytes", type=int, default=8 * 1024**3)
    df.add_argument("--no-resume", action="store_true")
    gp = s.add_parser("git-pair")
    gp.add_argument("--repo", required=True)
    gp.add_argument("--fixed-commit", required=True)
    gp.add_argument("--cwe", required=True)
    gp.add_argument("--out", required=True)
    gp.add_argument("--cve")
    cc = s.add_parser("capture-corpus")
    cc.add_argument("--manifest", required=True)
    cc.add_argument("--out-dir", required=True)
    cc.add_argument("--benchmark-out", required=True)
    cc.add_argument("--timeout", type=int, default=600)
    cc.add_argument("--slice-depth", type=int, default=8)
    cc.add_argument("--best-effort", action="store_true")
    cc.add_argument("--limit", type=int)
    mu = s.add_parser("mutate")
    mu.add_argument("--source", required=True)
    mu.add_argument("--recipes", required=True)
    mu.add_argument("--out-dir", required=True)

    pi = s.add_parser("provenance-index")
    pi.add_argument("--root", required=True)
    pi.add_argument("--out", required=True)
    pi.add_argument("--activity", default="artifact-index")
    pv = s.add_parser("provenance-verify")
    pv.add_argument("--manifest", required=True)
    sa = s.add_parser("sarif")
    sa.add_argument("--report", required=True)
    sa.add_argument("--out", required=True)
    si = s.add_parser("sarif-ingest")
    si.add_argument("--input", required=True)
    si.add_argument("--out", required=True)
    wv = s.add_parser("witness-validate")
    wv.add_argument("--report")
    wv.add_argument("--benchmark")
    wv.add_argument("--pattern")
    wv.add_argument("--max-cases", type=int)
    wv.add_argument("--only-expected", default="MATCH")
    pf = s.add_parser("performance")
    pf.add_argument("--benchmark", required=True)
    pf.add_argument("--pattern", required=True)
    pf.add_argument("--repeats", type=int, default=1)
    pf.add_argument("--partition")
    pf.add_argument("--max-case-seconds", type=float)
    fu = s.add_parser("fetch")
    fu.add_argument("--url", required=True)
    fu.add_argument("--out", required=True)
    fu.add_argument("--sha256")
    fu.add_argument("--timeout", type=int, default=120)
    fu.add_argument("--max-bytes", type=int, default=8 * 1024**3)
    fu.add_argument("--no-resume", action="store_true")
    tv = s.add_parser("tef-validate")
    tv.add_argument("--input", required=True)
    tv.add_argument("--out")
    tn = s.add_parser("tef-normalize")
    tn.add_argument("--input", required=True)
    tn.add_argument("--out", required=True)

    c = s.add_parser("cwe")
    cs = c.add_subparsers(dest="cwe_cmd", required=True)
    sy = cs.add_parser("sync")
    sy.add_argument("--out", default="catalog/cwe.json")
    sh = cs.add_parser("show")
    sh.add_argument("--catalog", required=True)
    sh.add_argument("--cwe", required=True)

    ev = s.add_parser("evidence", help="researcher-authored Evidence DSL operations")
    ecs = ev.add_subparsers(dest="evidence_cmd", required=True)
    evv = ecs.add_parser("validate")
    evv.add_argument("--spec", required=True)
    evc = ecs.add_parser("compile")
    evc.add_argument("--spec", required=True)
    evc.add_argument("--out", required=True)
    evi = ecs.add_parser("ir")
    evi.add_argument("--spec", required=True)
    evi.add_argument("--out", required=True)
    evr = ecs.add_parser("run")
    evr.add_argument("--spec", required=True)
    evr.add_argument("--graph", required=True)
    evr.add_argument("--out")
    evr.add_argument("--audit", action="store_true")

    eva = s.add_parser("evidence-validate", help="alias for evidence validate")
    eva.add_argument("--input", "--spec", dest="spec", required=True)
    evac = s.add_parser("evidence-compile", help="alias for evidence compile")
    evac.add_argument("--input", "--spec", dest="spec", required=True)
    evac.add_argument("--out", required=True)
    evat = s.add_parser("evidence-test", help="alias for evidence run")
    evat.add_argument("--evidence", "--spec", dest="spec", required=True)
    evat.add_argument("--graph", required=True)
    evat.add_argument("--out")
    evat.add_argument("--audit", action="store_true")

    dm = s.add_parser(
        "dataset-model-validate",
        help="validate a researcher-defined external-material mapping",
    )
    dm.add_argument("--model", required=True)
    dmp = s.add_parser(
        "dataset-model-preview", help="preview mapped cases without analysis"
    )
    dmp.add_argument("--model", required=True)
    dmp.add_argument("--limit", type=int, default=5)
    dmi = s.add_parser(
        "dataset-model-import",
        help="materialize a canonical experimental-material manifest from a mapping",
    )
    dmi.add_argument("--model", required=True)
    dmi.add_argument("--out", required=True)

    return p


def _write_outputs(payload: dict, fmt: str, out: str, report_dir: str) -> None:
    if fmt == "text":
        print(render_text(payload))
        return
    if fmt == "json":
        Path(out).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(out)
        return
    if fmt == "md":
        Path(out).write_text(render_markdown(payload), encoding="utf-8")
        print(out)
        return
    if fmt == "html":
        Path(out).write_text(render_html(payload), encoding="utf-8")
        print(out)
        return
    d = Path(report_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (d / "report.md").write_text(render_markdown(payload), encoding="utf-8")
    (d / "report.html").write_text(render_html(payload), encoding="utf-8")
    (d / "report.txt").write_text(render_text(payload), encoding="utf-8")
    print(render_text(payload))
    print(f"reports: {d}")


def graph_to_payload(g):
    return {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-canonical-graph",
        "digest": g.digest(),
        "metadata": g.metadata,
        "nodes": [
            {"id": n.id, "type": n.type, "properties": n.properties}
            for n in g.nodes.values()
        ],
        "edges": [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
            }
            for e in g.edges
        ],
    }


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "evidence":
            if args.evidence_cmd == "validate":
                r = validate_els(args.spec)
                print(json.dumps(r, ensure_ascii=False, indent=2))
                return 0 if r["status"] == "PASS" else 1
            if args.evidence_cmd in {"compile", "ir"}:
                r = write_compiled(args.spec, args.out)
                print(json.dumps(r, ensure_ascii=False, indent=2))
                return 0
            if args.evidence_cmd == "run":
                raw = compile_els_file(args.spec)
                pat = Pattern.from_dict(raw)
                g = parse_graph(args.graph)
                result = Matcher(g).run(pat).to_dict()
                if args.audit:
                    result["pattern_audit"] = [
                        x.to_dict() for x in audit_pattern(pat, {})
                    ]
                if args.out:
                    Path(args.out).resolve().parent.mkdir(parents=True, exist_ok=True)
                    Path(args.out).resolve().write_text(
                        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8",
                    )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get("status") == "MATCH" else 1
        if args.cmd == "evidence-validate":
            r = validate_els(args.spec)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "evidence-compile":
            r = write_compiled(args.spec, args.out)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "evidence-test":
            raw = compile_els_file(args.spec)
            pat = Pattern.from_dict(raw)
            g = parse_graph(args.graph)
            result = Matcher(g).run(pat).to_dict()
            if args.audit:
                result["pattern_audit"] = [x.to_dict() for x in audit_pattern(pat, {})]
            if args.out:
                Path(args.out).resolve().parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).resolve().write_text(
                    json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("status") == "MATCH" else 1
        if args.cmd == "dataset-model-validate":
            r = validate_model(args.model)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "dataset-model-preview":
            model_path = Path(args.model).resolve()
            data = materialize(model_path)
            limit = max(0, int(args.limit))
            out = {
                k: data[k]
                for k in (
                    "schema_version",
                    "format",
                    "dataset",
                    "mapping_sha256",
                    "case_count",
                )
            }
            out["cases"] = data["cases"][:limit]
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "dataset-model-import":
            r = write_materialized(args.model, args.out)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd in {"research-init", "init"}:
            print(init_research_project(args.cwe, args.out, args.overwrite))
            return 0
        if args.cmd == "family-init":
            print(
                init_evidence_family(
                    args.research_root,
                    args.family_id,
                    args.name,
                    args.research_question,
                    args.version,
                    args.overwrite,
                )
            )
            return 0
        if args.cmd == "research-record":
            record = {
                "experiment_id": args.experiment_id or "",
                "hypothesis": args.hypothesis,
                "tool": args.tool,
                "command": args.command,
                "result": args.result,
                "cases": args.case,
                "notes": args.notes,
            }
            log = append_experiment(args.root, record)
            print(log)
            return 0
        if args.cmd == "observation-record":
            r = record_observation(
                args.root,
                hypothesis_id=args.hypothesis_id,
                analyzer=args.analyzer,
                query=args.query,
                artifact=args.artifact,
                statement=args.statement,
                state=args.state,
                locations=[
                    json.loads(x)
                    if isinstance(x, str) and x.strip().startswith("{")
                    else {"value": x}
                    for x in args.location
                ],
                raw_digest=args.raw_digest,
                notes=args.notes,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "derivation-record":
            output = json.loads(args.output)
            replay = json.loads(args.replay) if args.replay else {}
            r = record_derivation(
                args.root,
                hypothesis_id=args.hypothesis_id,
                method=args.method,
                inputs=args.inputs,
                output=output,
                assumptions=args.assumption,
                state=args.state,
                evidence_definition=args.evidence_definition,
                replay=replay,
                notes=args.notes,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "research-status":
            base = audit_research_package(args.root, False)
            led = audit_research_ledgers(args.root)
            payload = {
                "schema_version": SCHEMA_VERSION,
                "tool_version": __version__,
                "package": base,
                "ledgers": led,
            }
            if args.profile:
                from .benchmark_build import benchmark_plan

                prof = load_profile(args.profile)
                plans = []
                for f in sorted(Path(args.root).glob("families/*/benchmark.json")):
                    plans.append(benchmark_plan(f, prof))
                payload["benchmark_plans"] = plans
            if args.hidden_root:
                payload["hidden"] = verify_hidden_bundle(args.hidden_root)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return (
                0 if base.get("status") != "FAIL" and led.get("status") != "FAIL" else 1
            )
        if args.cmd == "research-audit":
            r = audit_research_package(args.root, args.require_hidden)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] in {"PASS", "SCAFFOLD"} else 1
        if args.cmd == "research-evaluate":
            r = run_research_evaluation(
                args.root,
                args.profile,
                hidden_root=args.hidden_root,
                out=args.out,
                enforce_gates=args.enforce_gates,
                hidden_key_env=args.hidden_key_env,
            )
            if args.summary:
                compact = {
                    "schema_version": r["schema_version"],
                    "tool_version": r["tool_version"],
                    "status": r["status"],
                    "family_count": len(r["families"]),
                    "families": [
                        {
                            "family": x["family"],
                            "quality": x["quality"].get("status"),
                            "gate_errors": x.get("gates", []),
                            "evaluation_replay": (
                                x.get("evaluation", {}).get("independent_replay") or {}
                            ).get("status"),
                        }
                        for x in r["families"]
                    ],
                    "base_status": r.get("base_research_check", {}).get("status"),
                }
                print(json.dumps(compact, ensure_ascii=False, indent=2))
            else:
                print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "evaluate-benchmark":
            r = evaluate_benchmark(
                args.benchmark,
                args.pattern,
                args.out,
                partition=args.partition,
                replay=not args.no_replay,
                performance_repeats=args.performance_repeats,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "witness-replay":
            raw = json.loads(Path(args.report).read_text(encoding="utf-8"))
            r = replay_stored_report(raw, args.graph, Pattern.load(args.pattern))
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "witness-replay-batch":
            r = replay_stored_directory(args.results_dir, args.pattern)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "split-audit":
            r = audit_split_directory(args.dir, strategy=args.strategy)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "research-inventory":
            r = write_research_inventory(
                args.root,
                args.out,
                include_hidden=args.include_hidden,
                include_external_data=args.include_external_data,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "research-inventory-verify":
            r = verify_research_inventory(args.manifest)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "placeholder-audit":
            r = audit_no_placeholders(args.root, allow_scaffold=args.allow_scaffold)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") in {"PASS", "SCAFFOLD"} else 1
        if args.cmd == "research-bundle":
            r = bundle_research_package(
                args.root,
                args.out,
                include_hidden=args.include_hidden,
                include_external_data=args.include_external_data,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "research-readiness":
            r = research_readiness(
                args.root, args.profile, hidden_root=args.hidden_root
            )
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "research-build":
            r = build_external_research_corpus(
                args.input,
                args.out_dir,
                cwe=args.cwe,
                profile=args.profile,
                capture=not args.no_capture,
                timeout=args.timeout,
                limit=args.limit,
                split=not args.no_split,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "dataset-validate":
            from .benchmark_quality import quality_audit

            r = quality_audit(
                args.input,
                min_case_count=1,
                min_positive=0,
                min_negative=0,
                min_unknown=0,
                require_label_provenance=args.require_label_provenance,
                require_case_identity=args.require_case_identity,
            )
            raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
            missing_hash = sum(
                1
                for c in raw.get("cases", [])
                if not (
                    c.get("source_sha256")
                    or c.get("source_content_sha256")
                    or c.get("normalized_source_hash")
                    or (c.get("case_identity") or {}).get("source_sha256")
                )
            )
            r["source_hash_missing"] = missing_hash
            if args.require_source_hash and missing_hash:
                r["status"] = "FAIL"
                r.setdefault("errors", []).append(
                    f"source hash missing on {missing_hash} cases"
                )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "research-check":
            r = run_research_check(
                args.root,
                args.profile,
                args.hidden_root,
                args.enforce_gates,
                args.require_hidden,
                hidden_key_env=args.hidden_key_env,
            )
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            if args.summary:
                compact = {
                    "schema_version": r["schema_version"],
                    "tool_version": r["tool_version"],
                    "status": r["status"],
                    "family_count": r["family_count"],
                    "errors": r["errors"],
                    "families": [
                        {
                            "family": x["family"],
                            "pattern_audit": x["pattern_audit"]["status"],
                            "benchmark_audit": x.get("benchmark_audit", {}).get(
                                "status"
                            ),
                            "quality_audit": x.get("quality_audit", {}).get("status"),
                            "precision": x.get("metrics", {}).get("precision"),
                            "recall": x.get("metrics", {}).get("recall"),
                            "unknown_safety_rate": x.get("metrics", {}).get(
                                "unknown_safety_rate"
                            ),
                            "evidence_quality": x.get("evidence_quality", {}),
                            "independent_replay_rate": (
                                x.get("evidence_quality", {}) or {}
                            ).get("independent_replay_rate"),
                            "gate_errors": x.get("gate_errors", []),
                            "hidden_gate_errors": x.get("hidden_gate_errors", []),
                        }
                        for x in r["families"]
                    ],
                }
                print(json.dumps(compact, ensure_ascii=False, indent=2))
            else:
                print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "benchmark-split":
            print(
                json.dumps(
                    split_manifest(
                        args.manifest,
                        args.public_out,
                        args.hidden_out,
                        args.hidden_fraction,
                        args.seed,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "benchmark-compose":
            r = compose_benchmarks(
                args.input,
                args.out,
                copy_graphs=not args.no_copy_graphs,
                fail_on_conflicting_graph_label=not args.allow_conflicting_labels,
                include_unknown=not args.drop_unknown,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] in {"PASS", "WARN"} else 1
        if args.cmd == "benchmark-plan":
            r = benchmark_plan(args.benchmark, load_profile(args.profile))
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "hidden-seal":
            import os

            key = os.environ.get(args.key_env) if args.key_env else None
            r = seal_hidden_benchmark(
                args.benchmark,
                args.out,
                key,
                require_hmac=args.require_hmac,
                origin=args.origin,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "hidden-verify":
            import os

            key = os.environ.get(args.key_env) if args.key_env else None
            r = verify_hidden_bundle(
                args.bundle,
                key,
                require_hmac=args.require_hmac,
                require_external_origin=args.require_external_origin,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "schema-check":
            r = validate_json_schema(args.input, args.schema)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "migrate-pattern":
            r = migrate_pattern_to_current(
                args.pattern, args.out, family_id=args.family_id
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "benchmark-quality":
            from .benchmark_quality import quality_audit

            prof = load_profile(args.profile) if args.profile else {}
            gates = prof.get("gates", {}) if prof else {}
            r = quality_audit(
                args.benchmark,
                int(gates.get("min_total", args.min_cases)),
                int(gates.get("min_positive", args.min_positive)),
                int(gates.get("min_negative", args.min_negative)),
                int(gates.get("min_unknown", args.min_unknown)),
                min_real_world=int(prof.get("min_real_world_cases", 0) if prof else 0),
                required_dimensions=set(prof.get("required_dimensions", []))
                if prof
                else set(),
                dimension_minima=prof.get("dimension_minima", {}) if prof else {},
                min_dataset_sources=int(
                    prof.get("min_dataset_sources", 0) if prof else 0
                ),
                min_repositories=int(prof.get("min_repositories", 0) if prof else 0),
                min_projects=int(prof.get("min_projects", 0) if prof else 0),
                min_cves=int(prof.get("min_cves", 0) if prof else 0),
                require_split_strategies=set(prof.get("required_split_strategies", []))
                if prof
                else set(),
                require_label_provenance=bool(
                    prof.get("require_label_provenance", False)
                )
                if prof
                else False,
                require_case_identity=bool(prof.get("require_case_identity", False))
                if prof
                else False,
                min_real_world_label_authority=int(
                    (
                        prof.get(
                            "min_real_world_label_authority",
                            prof.get("require_real_world_label_authority", 0),
                        )
                        if prof
                        else 0
                    )
                    or 0
                ),
                require_negative_basis=bool(prof.get("require_negative_basis", False))
                if prof
                else False,
                require_source_similarity_audit=bool(
                    prof.get("require_source_similarity_audit", False)
                )
                if prof
                else False,
                source_similarity_threshold=float(
                    (prof.get("leakage_policy") or {}).get(
                        "normalized_source_similarity_threshold", 0.92
                    )
                    if prof
                    else 0.92
                ),
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "split":
            print(
                json.dumps(
                    split_benchmark(
                        args.manifest,
                        args.out_dir,
                        args.strategy,
                        args.train,
                        args.validation,
                        args.test,
                        args.seed,
                        args.allow_missing_group,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "split-chronological":
            print(
                json.dumps(
                    chronological_split(
                        args.manifest,
                        args.out_dir,
                        args.train,
                        args.validation,
                        args.allow_missing_date,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "corpus-inventory":
            payload = {
                "schema_version": SCHEMA_VERSION,
                "root": str(Path(args.root).resolve()),
                "files": source_inventory(args.root),
            }
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(args.out)
            return 0
        if args.cmd == "corpus-tags":
            payload = tag_matrix(args.manifest)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            return 0
        if args.cmd == "coverage-matrix":
            raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            payload = build_coverage_matrix(raw.get("cases", []))
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            return 0
        if args.cmd == "leakage-audit":
            r = audit_source_files(args.source, args.threshold, args.max_comparisons)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] in {"PASS", "WARN"} else 1
        if args.cmd == "leakage-audit-manifest":
            raw = json.loads(Path(args.benchmark).read_text(encoding="utf-8"))
            base = Path(args.benchmark).resolve().parent
            src = []
            for case in raw.get("cases", []):
                sp = case.get("source")
                if sp:
                    candidate = (base / str(sp)).resolve()
                    if candidate.is_file():
                        src.append(str(candidate))
            if not src:
                raise ValueError(
                    "benchmark contains no readable source paths for leakage audit"
                )
            r = audit_source_files(src, args.threshold, args.max_comparisons)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] in {"PASS", "WARN"} else 1
        if args.cmd == "lineage-audit":
            r = audit_benchmark_lineage(args.benchmark)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                )
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "dataset-import-juliet":
            print(
                json.dumps(
                    import_juliet(
                        args.root,
                        args.out,
                        args.cwe,
                        args.partition,
                        args.copy_source,
                        args.copy_root,
                        args.label_mode,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-import-sard":
            print(
                json.dumps(
                    import_sard_table(args.input, args.out, args.cwe, args.source_root),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-import-primevul":
            print(
                json.dumps(
                    import_primevul_jsonl(
                        args.input, args.out, args.source_root, args.cwe
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-import-secvuleval":
            print(
                json.dumps(
                    import_secvuleval_jsonl(
                        args.input, args.out, args.source_root, args.cwe
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-import-diversevul":
            print(
                json.dumps(
                    import_diversevul_jsonl(
                        args.input, args.out, args.source_root, args.cwe
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-merge":
            print(
                json.dumps(
                    merge_dataset_manifests(args.input, args.out),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "dataset-index-archive":
            from .datasets import index_dataset_archive

            r = index_dataset_archive(args.archive, args.out)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "dataset-registry":
            raw = json.loads(Path(args.file).read_text(encoding="utf-8"))
            print(json.dumps(raw, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "dataset-fetch":
            r = fetch_registry_dataset(
                args.registry,
                args.id,
                args.out,
                args.timeout,
                not args.no_resume,
                args.artifact,
                args.max_bytes,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "git-pair":
            print(
                json.dumps(
                    build_commit_pair(
                        args.repo, args.fixed_commit, args.cwe, args.out, args.cve
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "capture-corpus":
            print(
                json.dumps(
                    capture_dataset(
                        args.manifest,
                        args.out_dir,
                        args.benchmark_out,
                        args.timeout,
                        args.slice_depth,
                        args.best_effort,
                        args.limit,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "mutate":
            recipes = json.loads(Path(args.recipes).read_text(encoding="utf-8"))
            if isinstance(recipes, dict):
                recipes = recipes.get("recipes", [])
            if not isinstance(recipes, list):
                raise ValueError(
                    "recipes file must contain an array or {recipes:[...]}"
                )
            print(
                json.dumps(
                    mutate_file(args.source, recipes, args.out_dir),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.cmd == "provenance-index":
            r = build_provenance_manifest(
                args.root, out=args.out, activity=args.activity
            )
            print(args.out)
            return 0
        if args.cmd == "provenance-verify":
            r = verify_artifact_manifest(args.manifest)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "sarif-ingest":
            g = sarif_to_graph(args.input)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(graph_to_payload(g), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(args.out)
            return 0
        if args.cmd == "witness-validate":
            if args.report:
                r = validate_report(args.report)
            elif args.benchmark and args.pattern:
                r = validate_benchmark_matches(
                    args.benchmark,
                    Pattern.load(args.pattern),
                    max_cases=args.max_cases,
                    only_status=args.only_expected,
                )
            else:
                raise ValueError(
                    "witness-validate requires --report or --benchmark + --pattern"
                )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "performance":
            pat = Pattern.load(args.pattern)
            r = profile_pattern(
                args.benchmark, pat, args.repeats, args.partition, args.max_case_seconds
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "fetch":
            r = fetch_url(
                args.url,
                args.out,
                args.sha256,
                args.timeout,
                not args.no_resume,
                args.max_bytes,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "tef-validate":
            raw = load_document(args.input)
            errors = validate_tef(raw)
            payload = {
                "format": "TEF",
                "status": "PASS" if not errors else "FAIL",
                "errors": errors,
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            if args.out:
                Path(args.out).write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            return 0 if not errors else 1
        if args.cmd == "tef-normalize":
            raw = load_document(args.input)
            notes = to_evidencelab_notes(raw)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(notes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            print(args.out)
            return 0
        if args.cmd == "cwe":
            if args.cwe_cmd == "sync":
                print(json.dumps(sync_catalog(args.out), ensure_ascii=False, indent=2))
                return 0
            item = get(load_catalog(args.catalog), args.cwe)
            print(json.dumps(item, ensure_ascii=False, indent=2))
            return 0 if item else 1
        if args.cmd == "doctor":
            r = doctor_run()
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "scan":
            patterns = list(args.pattern or [])
            if args.family_root:
                patterns.extend(
                    str(p)
                    for p in sorted(Path(args.family_root).glob("*/pattern.json"))
                    if p.is_file()
                )
            if not patterns:
                raise ValueError(
                    "scan requires at least one --pattern or --family-root"
                )
            r = scan_source(
                args.source,
                patterns,
                args.out,
                dataflow_timeout=args.dataflow_timeout,
                dataflow_slice_depth=args.dataflow_slice_depth,
                keep_capture=not args.no_capture_retention,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "capture":
            r = capture_joern(
                args.source,
                args.out,
                graphson=not args.no_graphson,
                dataflow=not args.no_dataflow,
                dataflow_timeout=args.dataflow_timeout,
                dataflow_slice_depth=args.dataflow_slice_depth,
                dataflow_file_filter=args.dataflow_file_filter,
                dataflow_method_name_filter=args.dataflow_method_name_filter,
                best_effort_dataflow=args.best_effort_dataflow,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r.get("status") == "PASS" else 1
        if args.cmd == "inspect":
            g = parse_graph(args.graph)
            print(
                json.dumps(
                    g.detailed_summary() if args.detailed else g.summary(),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0 if not args.strict or g.metadata.get("parse_health") == "OK" else 1
        if args.cmd == "normalize":
            g = enrich_graph(parse_graph(args.graph))
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(
                    graph_to_payload(g),
                    ensure_ascii=False,
                    indent=2 if args.pretty else None,
                ),
                encoding="utf-8",
            )
            print(args.out)
            return 0
        if args.cmd == "merge":
            from .scanner import _merge

            merge_paths = [Path(path).resolve() for path in args.graph]
            merged = _merge(merge_paths)
            if args.manifest:
                merged.metadata["analysis_attestation"] = (
                    validate_capture_manifest_for_merge(args.manifest, args.graph)
                )
                merged.metadata["capture_manifest"] = str(Path(args.manifest).resolve())
            else:
                merged.metadata.pop("analysis_attestation", None)
                merged.metadata.pop("capture_manifest", None)

            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(
                    graph_to_payload(merged),
                    ensure_ascii=False,
                    indent=2 if args.pretty else None,
                ),
                encoding="utf-8",
            )
            print(args.out)
            return 0
        if args.cmd == "benchmark-audit":
            pat = Pattern.load(args.pattern)
            r = audit_benchmark_manifest(args.benchmark, pat)
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0 if r["status"] == "PASS" else 1
        if args.cmd == "audit":
            pat = Pattern.load(args.pattern)
            prof = load_profile(args.profile) if args.profile else {}
            findings = audit_pattern(pat, prof.get("audit", {}))
            payload = {
                "schema_version": SCHEMA_VERSION,
                "pattern": {
                    "id": pat.pattern_id,
                    "cwe": pat.cwe,
                    "version": pat.version,
                },
                "audit": {
                    "status": "PASS"
                    if not any(x.severity == "ERROR" for x in findings)
                    else "FAIL",
                    "findings": [x.to_dict() for x in findings],
                },
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0 if payload["audit"]["status"] == "PASS" else 1
        if args.cmd == "validate":
            pat = Pattern.load(args.pattern)
            prof = load_profile(args.profile) if args.profile else {}
            findings = audit_pattern(pat, prof.get("audit", {}))
            payload = {
                "schema_version": SCHEMA_VERSION,
                "pattern": {
                    "id": pat.pattern_id,
                    "cwe": pat.cwe,
                    "version": pat.version,
                },
                "audit": {
                    "status": "PASS"
                    if not any(x.severity == "ERROR" for x in findings)
                    else "FAIL",
                    "findings": [x.to_dict() for x in findings],
                },
            }
            if bool(args.graph) == bool(args.benchmark):
                raise EvidenceLabError("provide exactly one of --graph or --benchmark")
            pe = validate_profile(pat, prof) if prof else []
            payload["profile"] = {"status": "PASS" if not pe else "FAIL", "errors": pe}
            if args.graph:
                g = parse_graph(args.graph)
                m = Matcher(g).run(pat)
                payload["graph"] = g.summary()
                payload["graph_digest"] = g.digest()
                payload["match"] = m.to_dict()
                payload["status"] = (
                    "PASS"
                    if m.status == "MATCH"
                    and not pe
                    and payload["audit"]["status"] == "PASS"
                    else ("PARTIAL" if m.status == "PARTIAL" else "FAIL")
                )
            else:
                _, metrics, meta = run_manifest(
                    args.benchmark, pat, reveal=not args.hide_cases, partition=None
                )
                md = metrics.to_dict()
                payload["metrics"] = md
                payload["benchmark"] = {
                    k: v for k, v in meta.items() if k != "manifest_id"
                }
                payload["manifest_id"] = meta.get("manifest_id")
                payload["benchmark_audit"] = meta.get("benchmark_audit")
                payload["gate_errors"] = (
                    validate_benchmark_gate(md, meta, prof, args.hidden) if prof else []
                )
                payload["status"] = (
                    "PASS"
                    if not payload["gate_errors"]
                    and not pe
                    and payload["audit"]["status"] == "PASS"
                    else "FAIL"
                )
            _write_outputs(payload, args.format, args.out, args.report_dir)
            return 0 if payload.get("status") == "PASS" else 1
        if args.cmd == "sarif":
            print(write_sarif(args.report, args.out))
            return 0
        if args.cmd == "make-submission":
            create_submission_manifest(
                args.root, args.cwe, args.pattern, args.graph, args.public_benchmark
            )
            print(args.root)
            return 0
        if args.cmd == "validate-submission":
            result = validate_submission(
                args.submission,
                args.profile,
                args.hidden_benchmark,
                args.report_dir,
                args.hide_cases,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("status") == "PASS" else 1
    except (
        EvidenceLabError,
        ValueError,
        OSError,
        json.JSONDecodeError,
        RuntimeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2
