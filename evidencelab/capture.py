from __future__ import annotations
from . import SCHEMA_VERSION, __version__
from pathlib import Path
import os, signal, shutil, subprocess, re, json
from .errors import EvidenceLabError


def _run(cmd, cwd=None, timeout=1800):
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(
            cmd, timeout, output=stdout, stderr=stderr
        ) from exc
    if proc.returncode != 0:
        raise EvidenceLabError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{stdout}\n{stderr}"
        )
    return stdout, stderr


def _sha256_path(path: str | Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def joern_version() -> str | None:
    exe = shutil.which("joern")
    if not exe:
        return None
    try:
        out, err = _run([exe, "--help"], timeout=20)
        m = re.search(r"Version:\s*([^\s]+)", out + err)
        return m.group(1) if m else None
    except Exception:
        try:
            p = subprocess.run(
                [exe], input=":exit\n", text=True, capture_output=True, timeout=20
            )
            m = re.search(r"Version:\s*([^\s]+)", p.stdout + p.stderr)
            return m.group(1) if m else None
        except Exception:
            return None


def _find_export(folder: Path, exts: tuple[str, ...]) -> Path | None:
    for p in sorted(folder.iterdir() if folder.exists() else []):
        if p.is_file() and p.suffix.lower() in exts:
            return p
    exports = sorted(folder.glob("export.*")) if folder.exists() else []
    return exports[0] if exports else None


def capture_joern(
    source: str | Path,
    out: str | Path,
    graphson: bool = True,
    dataflow: bool = True,
    dataflow_timeout: int = 300,
    dataflow_slice_depth: int = 8,
    dataflow_file_filter: str | None = None,
    dataflow_method_name_filter: str | None = None,
    best_effort_dataflow: bool = False,
) -> dict:
    src = Path(source).resolve()
    root = Path(out).resolve()
    if not src.exists():
        raise EvidenceLabError(f"source does not exist: {src}")
    if not shutil.which("joern-parse"):
        raise EvidenceLabError("joern-parse is not installed")
    if not shutil.which("joern-export"):
        raise EvidenceLabError("joern-export is not installed")
    root.mkdir(parents=True, exist_ok=True)
    cpg = root / "cpg.bin"
    gm = root / "graphml"
    gs = root / "graphson"
    dfbase = root / "dataflow"
    # Joern expects its --out directory not to exist. Capture must therefore
    # remove stale artifacts before every invocation so reruns are idempotent.
    if cpg.exists():
        cpg.unlink()
    for export_dir in (gm, gs):
        if export_dir.exists():
            shutil.rmtree(export_dir)
    for stale in (Path(str(dfbase) + ".json"), dfbase):
        if stale.is_file():
            stale.unlink()
        elif stale.is_dir():
            shutil.rmtree(stale)
    stdout = {}
    if dataflow_timeout < 1:
        raise ValueError("dataflow_timeout must be positive")
    if dataflow_slice_depth < 1:
        raise ValueError("dataflow_slice_depth must be positive")
    out1, err1 = _run(["joern-parse", str(src), "--output", str(cpg)])
    stdout["parse"] = {"stdout": out1, "stderr": err1}
    out2, err2 = _run(
        ["joern-export", str(cpg), "--repr=all", "--format=graphml", "--out", str(gm)]
    )
    stdout["graphml"] = {"stdout": out2, "stderr": err2}
    graphml = _find_export(gm, (".xml", ".graphml"))
    if graphml is None:
        raise EvidenceLabError("joern-export produced no GraphML file")
    graphson_file = None
    if graphson:
        out3, err3 = _run(
            [
                "joern-export",
                str(cpg),
                "--repr=all",
                "--format=graphson",
                "--out",
                str(gs),
            ]
        )
        stdout["graphson"] = {"stdout": out3, "stderr": err3}
        graphson_file = _find_export(gs, (".json", ".graphson"))
    dataflow_file = None
    dataflow_status = "NOT_REQUESTED"
    if dataflow:
        slice_cmd = ["joern-slice", "data-flow"]
        if dataflow_slice_depth:
            slice_cmd += ["--slice-depth", str(dataflow_slice_depth)]
        if dataflow_file_filter:
            slice_cmd += ["--file-filter", dataflow_file_filter]
        if dataflow_method_name_filter:
            slice_cmd += ["--method-name-filter", dataflow_method_name_filter]
        slice_cmd += [str(cpg), "-o", str(dfbase)]
        try:
            out4, err4 = _run(slice_cmd, timeout=dataflow_timeout)
            stdout["dataflow"] = {
                "stdout": out4,
                "stderr": err4,
                "status": "OK",
                "slice_depth": dataflow_slice_depth,
            }
            dataflow_status = "OK"
        except subprocess.TimeoutExpired as exc:
            stdout["dataflow"] = {
                "status": "TIMEOUT",
                "timeout_seconds": dataflow_timeout,
                "slice_depth": dataflow_slice_depth,
                "stdout": getattr(exc, "stdout", "") or "",
                "stderr": getattr(exc, "stderr", "") or "",
            }
            dataflow_status = "TIMEOUT"
            if not best_effort_dataflow:
                raise EvidenceLabError(
                    f"joern-slice data-flow timed out after {dataflow_timeout}s"
                ) from exc
        except EvidenceLabError as exc:
            stdout["dataflow"] = {
                "status": "FAILED",
                "error": str(exc),
                "slice_depth": dataflow_slice_depth,
            }
            dataflow_status = "FAILED"
            if not best_effort_dataflow:
                raise
        cand = Path(str(dfbase) + ".json")
        if cand.exists():
            dataflow_file = cand
            dataflow_status = "OK"
    manifest = {
        "format": "evidencelab-capture",
        "version": SCHEMA_VERSION,
        "tool_version": __version__,
        "source": str(src),
        "source_sha256": _sha256_path(src),
        "joern_version": joern_version(),
        "artifacts": {
            "cpg": str(cpg),
            "graphml": str(graphml),
            "graphson": str(graphson_file) if graphson_file else None,
            "dataflow": str(dataflow_file) if dataflow_file else None,
        },
        "analysis": {
            "dataflow": {
                "requested": dataflow,
                "status": dataflow_status,
                "timeout_seconds": dataflow_timeout if dataflow else None,
                "slice_depth": dataflow_slice_depth if dataflow else None,
                "file_filter": dataflow_file_filter,
                "method_name_filter": dataflow_method_name_filter,
                "best_effort": best_effort_dataflow,
            }
        },
        "analysis_attestation": {
            "level": "ANALYZER_ATTESTED"
            if dataflow_status in {"OK", "NOT_REQUESTED"}
            else "ANALYZER_DEGRADED",
            "analyzer": "Joern",
            "analyzer_version": joern_version(),
            "source_sha256": _sha256_path(src),
            "capture_status": (
                "PASS" if dataflow_status in {"OK", "NOT_REQUESTED"} else "DEGRADED"
            ),
        },
        "commands": stdout,
        "status": (
            "PASS" if dataflow_status in {"OK", "NOT_REQUESTED"} else "DEGRADED"
        ),
    }
    (root / "capture-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest
