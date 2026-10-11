from __future__ import annotations
import json, os, signal, subprocess, sys
from pathlib import Path
from evidencelab import SCHEMA_VERSION

root = Path(__file__).resolve().parents[1]
manifest = json.loads(
    (root / "examples/cwe-120/joern-e2e-manifest.json").read_text(encoding="utf-8")
)
out = Path(os.environ.get("CWE120_E2E_OUT", "/tmp/evidencelab-cwe120-e2e")).resolve()
timeout = int(os.environ.get("CWE120_E2E_CASE_TIMEOUT", "600"))
slice_depth = os.environ.get("CWE120_E2E_SLICE_DEPTH", "8")
dataflow_timeout = os.environ.get("CWE120_E2E_DATAFLOW_TIMEOUT", "240")
strict = os.environ.get("CWE120_E2E_STRICT", "0") == "1"
out.mkdir(parents=True, exist_ok=True)


def run(cmd, timeout, log=None):
    kw = {"start_new_session": True}
    if log:
        f = log.open("w", encoding="utf-8")
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, **kw)
    else:
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw
        )
    try:
        if log:
            rc = p.wait(timeout=timeout)
            f.close()
            return rc, ""
        a, b = p.communicate(timeout=timeout)
        return p.returncode, (a or "") + (b or "")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        if log:
            f.close()
        raise


rows = []
for i, item in enumerate(manifest["cases"], 1):
    cid = item["id"]
    src = root / item["source"]
    case = out / cid
    case.mkdir(parents=True, exist_ok=True)
    log = case / "e2e.log"
    print(f"[{i}/{len(manifest['cases'])}] {cid}: CAPTURE", flush=True)
    cap = [
        sys.executable,
        "-m",
        "evidencelab",
        "capture",
        "--source",
        str(src),
        "--out",
        str(case),
        "--dataflow-slice-depth",
        slice_depth,
        "--dataflow-timeout",
        dataflow_timeout,
        "--dataflow-file-filter",
        src.name,
        "--best-effort-dataflow",
    ]
    try:
        rc, _ = run(cap, timeout, log)
    except subprocess.TimeoutExpired:
        print(f"[{i}/{len(manifest['cases'])}] {cid}: TIMEOUT", flush=True)
        rows.append({"id": cid, "status": "TIMEOUT", "log": str(log)})
        continue
    if rc != 0:
        rows.append(
            {"id": cid, "status": "CAPTURE_FAILED", "log": str(log), "returncode": rc}
        )
        print(f"[{i}/{len(manifest['cases'])}] {cid}: CAPTURE_FAILED", flush=True)
        continue
    merged = case / "merged.json"
    gm = case / "graphml" / "export.xml"
    df = case / "dataflow.json"
    if not gm.is_file():
        rows.append({"id": cid, "status": "MISSING_GRAPHML", "log": str(log)})
        continue
    print(f"[{i}/{len(manifest['cases'])}] {cid}: MERGE", flush=True)
    merge = [sys.executable, "-m", "evidencelab", "merge", "--graph", str(gm)]
    if df.is_file():
        merge += ["--graph", str(df)]
    merge += ["--out", str(merged), "--pretty"]
    rc, txt = run(merge, timeout, None)
    if rc != 0:
        rows.append({"id": cid, "status": "MERGE_FAILED", "detail": txt[-4000:]})
        continue
    actuals = []
    case_ok = True
    expected_map = item.get("expected", {})
    for fam in item["families"]:
        pattern = root / "examples/cwe-120/families" / fam / "pattern.json"
        rep = case / f"{fam}-report.json"
        cmd = [
            sys.executable,
            "-m",
            "evidencelab",
            "validate",
            "--graph",
            str(merged),
            "--pattern",
            str(pattern),
            "--format",
            "json",
            "--out",
            str(rep),
        ]
        rc, txt = run(cmd, timeout, None)
        actual = "ERROR"
        try:
            actual = json.loads(rep.read_text())["match"]["status"]
        except Exception:
            pass
        expected = expected_map.get(fam)
        ok = rc == 0 and (expected is None or actual == expected)
        case_ok = case_ok and ok
        actuals.append(
            {
                "family": fam,
                "status": actual,
                "expected": expected,
                "ok": ok,
                "exit_code": rc,
                "report": str(rep),
            }
        )
    status = "PASS" if case_ok else "VALIDATION_MISMATCH"
    rows.append(
        {
            "id": cid,
            "status": status,
            "families": actuals,
            "log": str(log),
            "merged": str(merged),
        }
    )
    print(f"[{i}/{len(manifest['cases'])}] {cid}: {status}", flush=True)

failed = [r for r in rows if r.get("status") not in {"PASS"}]
payload = {
    "schema_version": SCHEMA_VERSION,
    "status": "FAIL" if failed or len(rows) != len(manifest["cases"]) else "PASS",
    "case_count": len(rows),
    "failed_count": len(failed),
    "cases": rows,
    "timeout_seconds": timeout,
}
(out / "e2e-report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
print(json.dumps(payload, indent=2))
sys.exit(1 if payload["status"] == "FAIL" else 0)
