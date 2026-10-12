from __future__ import annotations
from . import SCHEMA_VERSION, __version__
from pathlib import Path
import os, signal, shutil, subprocess, re, json
import xml.etree.ElementTree as ET
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
    """Hash a file compatibly, or a directory deterministically.

    File inputs keep the historical byte-for-byte SHA-256. Directory inputs are
    hashed from sorted relative paths, entry types, symlink targets, and file bytes;
    absolute paths and timestamps are deliberately excluded.
    """
    import hashlib

    target = Path(path)
    if target.is_file():
        h = hashlib.sha256()
        with target.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    if not target.is_dir():
        raise EvidenceLabError(
            f"source path is not a regular file or directory: {target}"
        )

    h = hashlib.sha256()
    h.update(b"EvidenceLab directory digest v1\0")

    entries: list[Path] = []

    def _raise_walk_error(error: OSError) -> None:
        raise EvidenceLabError(
            f"unable to hash source directory: {error}"
        ) from error

    for current, dirnames, filenames in os.walk(
        target, followlinks=False, onerror=_raise_walk_error
    ):
        dirnames.sort()
        filenames.sort()
        base = Path(current)
        # Include directories too, so empty directories contribute to the digest.
        entries.extend(base / name for name in dirnames)
        entries.extend(base / name for name in filenames)
    entries.sort(key=lambda item: item.relative_to(target).as_posix())

    for entry in entries:
        relative = entry.relative_to(target).as_posix().encode(
            "utf-8", errors="surrogateescape"
        )
        h.update(len(relative).to_bytes(8, "big"))
        h.update(relative)
        if entry.is_symlink():
            h.update(b"L")
            link_target = os.fsencode(os.readlink(entry))
            h.update(len(link_target).to_bytes(8, "big"))
            h.update(link_target)
        elif entry.is_dir():
            h.update(b"D")
        elif entry.is_file():
            h.update(b"F")
            h.update(entry.stat().st_size.to_bytes(8, "big"))
            with entry.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        else:
            raise EvidenceLabError(
                f"unsupported special file in source directory: {entry}"
            )
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


def _validate_graphml(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            tail = b""
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                scan = (tail + chunk).upper()
                if b"<!DOCTYPE" in scan or b"<!ENTITY" in scan:
                    raise EvidenceLabError(
                        f"GraphML output with DTD/entity declarations is rejected: {path}"
                    )
                tail = scan[-16:]
    except OSError as exc:
        raise EvidenceLabError(
            f"unable to read GraphML output: {path}"
        ) from exc

    root_tag = None
    graph_found = False
    graph_depth = None
    node_count = 0
    node_ids = set()
    edge_refs = []
    invalid_node = False
    invalid_edge = False
    stack = []

    try:
        for event, element in ET.iterparse(path, events=("start", "end")):
            tag = str(element.tag).rsplit("}", 1)[-1].lower()
            if event == "start":
                if not stack:
                    root_tag = tag
                if not graph_found and tag == "graph":
                    graph_found = True
                    graph_depth = len(stack)
                elif graph_depth is not None and len(stack) == graph_depth + 1:
                    if tag == "node":
                        node_id = element.attrib.get("id")
                        if not node_id or node_id in node_ids:
                            invalid_node = True
                        else:
                            node_count += 1
                            node_ids.add(node_id)
                    elif tag == "edge":
                        source = element.attrib.get("source")
                        target = element.attrib.get("target")
                        if not source or not target:
                            invalid_edge = True
                        else:
                            edge_refs.append((source, target))
                stack.append(element)
            else:
                if (
                    graph_depth is not None
                    and len(stack) == graph_depth + 1
                    and tag == "graph"
                ):
                    graph_depth = None
                if stack:
                    parent = stack[-2] if len(stack) > 1 else None
                    stack.pop()
                    if parent is not None:
                        parent.remove(element)
                    element.clear()
    except (ET.ParseError, OSError) as exc:
        raise EvidenceLabError(
            f"joern-export produced invalid GraphML output: {path}"
        ) from exc

    dangling_edge = any(
        source not in node_ids or target not in node_ids
        for source, target in edge_refs
    )
    if (
        root_tag != "graphml"
        or not graph_found
        or node_count == 0
        or invalid_node
        or invalid_edge
        or dangling_edge
    ):
        raise EvidenceLabError(
            f"joern-export produced invalid or empty GraphML output: {path}"
        )


def _unwrap_graphson_id(value):
    while isinstance(value, dict) and "@value" in value:
        value = value["@value"]
    return value


def _validate_graphson(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceLabError(
            f"joern-export produced invalid GraphSON output: {path}"
        ) from exc

    if (
        isinstance(payload, dict)
        and "@value" in payload
        and str(payload.get("@type", "")).lower() in {"tinker:graph", "graph"}
    ):
        payload = payload["@value"]
    elif isinstance(payload, dict) and isinstance(payload.get("graph"), dict):
        payload = payload["graph"]

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("vertices"), list)
        or not isinstance(payload.get("edges"), list)
    ):
        raise EvidenceLabError(
            f"joern-export produced invalid GraphSON output: {path}"
        )

    vertices = payload["vertices"]
    edges = payload["edges"]
    if not vertices:
        raise EvidenceLabError(
            f"joern-export produced an empty GraphSON graph: {path}"
        )

    vertex_ids = set()
    for vertex in vertices:
        if not isinstance(vertex, dict) or vertex.get("id") is None:
            raise EvidenceLabError(
                f"joern-export produced an invalid GraphSON vertex: {path}"
            )
        vertex_id = _unwrap_graphson_id(vertex["id"])
        if vertex_id is None:
            raise EvidenceLabError(
                f"joern-export produced an invalid GraphSON vertex id: {path}"
            )
        key = str(vertex_id)
        if key in vertex_ids:
            raise EvidenceLabError(
                f"joern-export produced duplicate GraphSON vertex ids: {path}"
            )
        vertex_ids.add(key)

    for edge in edges:
        if not isinstance(edge, dict):
            raise EvidenceLabError(
                f"joern-export produced an invalid GraphSON edge: {path}"
            )
        source = _unwrap_graphson_id(edge.get("outV", edge.get("source")))
        target = _unwrap_graphson_id(edge.get("inV", edge.get("target")))
        if source is None or target is None:
            raise EvidenceLabError(
                f"joern-export produced an invalid GraphSON edge: {path}"
            )
        if str(source) not in vertex_ids or str(target) not in vertex_ids:
            raise EvidenceLabError(
                f"joern-export produced a GraphSON edge with missing endpoints: {path}"
            )


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
    _validate_graphml(graphml)
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
        if graphson_file is None:
            raise EvidenceLabError("joern-export produced no GraphSON file")
        _validate_graphson(graphson_file)
    dataflow_file = None
    dataflow_status = "NOT_REQUESTED"
    if dataflow:
        def discard_dataflow_output() -> None:
            candidate = Path(str(dfbase) + ".json")
            try:
                if candidate.is_symlink() or candidate.is_file():
                    candidate.unlink()
                elif candidate.is_dir():
                    shutil.rmtree(candidate)
            except OSError as exc:
                raise EvidenceLabError(
                    f"unable to remove invalid dataflow output: {candidate}"
                ) from exc

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
            cand = Path(str(dfbase) + ".json")
            if not cand.is_file():
                raise EvidenceLabError(
                    "joern-slice data-flow produced no JSON output"
                )
            try:
                with cand.open("r", encoding="utf-8") as stream:
                    payload = json.load(stream)
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise EvidenceLabError(
                    "joern-slice data-flow produced invalid JSON output"
                ) from exc
            if (
                not isinstance(payload, dict)
                or payload.get("$type") != "DataFlowSlice"
                or not isinstance(payload.get("nodes"), list)
                or not isinstance(payload.get("edges"), list)
                or any(
                    not isinstance(node, dict) or node.get("id") is None
                    for node in payload["nodes"]
                )
                or any(
                    not isinstance(edge, dict)
                    or edge.get("src") is None
                    or edge.get("dst") is None
                    for edge in payload["edges"]
                )
            ):
                raise EvidenceLabError(
                    "joern-slice data-flow JSON output does not match DataFlowSlice schema"
                )
            dataflow_file = cand
            stdout["dataflow"] = {
                "stdout": out4,
                "stderr": err4,
                "status": "OK",
                "slice_depth": dataflow_slice_depth,
            }
            dataflow_status = "OK"
        except subprocess.TimeoutExpired as exc:
            discard_dataflow_output()
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
            discard_dataflow_output()
            stdout["dataflow"] = {
                "status": "FAILED",
                "error": str(exc),
                "slice_depth": dataflow_slice_depth,
            }
            dataflow_status = "FAILED"
            if not best_effort_dataflow:
                raise
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
