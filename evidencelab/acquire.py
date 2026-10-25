from __future__ import annotations
from . import SCHEMA_VERSION, __version__
from pathlib import Path
from urllib.request import Request, urlopen
import hashlib, json, os, time

USER_AGENT = f"EvidenceLab/{__version__} dataset-fetcher"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(
    url: str,
    out: str | Path,
    sha256: str | None = None,
    timeout: int = 120,
    resume: bool = True,
    max_bytes: int | None = 8 * 1024**3,
) -> dict:
    dst = Path(out).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(dst) + ".part")
    start = tmp.stat().st_size if resume and tmp.is_file() else 0
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            **({"Range": f"bytes={start}-"} if start else {}),
        },
    )
    started = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            response_status = getattr(resp, "status", 200)
            append = bool(start and response_status == 206)
            if append:
                content_range = resp.headers.get("Content-Range", "")
                if not content_range.lower().startswith(f"bytes {start}-"):
                    tmp.unlink(missing_ok=True)
                    raise ValueError("INVALID_CONTENT_RANGE_FOR_RESUME")
            elif response_status == 206:
                tmp.unlink(missing_ok=True)
                raise ValueError("UNEXPECTED_PARTIAL_RESPONSE")
            else:
                start = 0
            content_length = resp.headers.get("Content-Length")
            expected_total = (
                start + int(content_length)
                if append and content_length is not None
                else (int(content_length) if content_length is not None else None)
            )
            if (
                max_bytes is not None
                and expected_total is not None
                and expected_total > int(max_bytes)
            ):
                return {
                    "status": "FAIL",
                    "error": "DOWNLOAD_EXCEEDS_MAX_BYTES",
                    "max_bytes": int(max_bytes),
                    "declared_bytes": expected_total,
                    "url": url,
                    "out": str(dst),
                }
            mode = "ab" if append else "wb"
            downloaded = start
            with tmp.open(mode) as f:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if max_bytes is not None and downloaded > int(max_bytes):
                        raise ValueError("DOWNLOAD_EXCEEDS_MAX_BYTES")
                    f.write(chunk)
    except Exception as exc:
        return {
            "status": "FAIL",
            "error": str(exc),
            "url": url,
            "out": str(dst),
            "partial": str(tmp) if tmp.exists() else None,
        }
    tmp.replace(dst)
    digest = sha256_file(dst)
    if sha256 and digest.lower() != sha256.lower():
        dst.unlink(missing_ok=True)
        return {
            "status": "FAIL",
            "error": "SHA256_MISMATCH",
            "url": url,
            "expected_sha256": sha256,
            "actual_sha256": digest,
        }
    return {
        "status": "PASS",
        "url": url,
        "out": str(dst),
        "bytes": dst.stat().st_size,
        "sha256": digest,
        "resumed": bool(resume and start),
        "elapsed_seconds": round(time.time() - started, 3),
    }


def write_acquisition_record(out: str | Path, record: dict) -> None:
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def fetch_registry_dataset(
    registry_path: str | Path,
    dataset_id: str,
    out: str | Path,
    timeout: int = 300,
    resume: bool = True,
    artifact_id: str | None = None,
    max_bytes: int | None = 8 * 1024**3,
) -> dict:
    """Fetch a registry dataset or one of its explicitly pinned artifacts.

    Repository/Hugging Face landing pages are never guessed as raw files. When a dataset
    declares multiple artifacts, the caller must select the artifact explicitly. Every
    acquisition records the registry entry, selected artifact, URL, expected digest and
    actual digest in a sidecar JSON document.
    """
    registry = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    item = next(
        (
            x
            for x in registry.get("datasets", [])
            if str(x.get("id")) == str(dataset_id)
        ),
        None,
    )
    if not item:
        return {"status": "FAIL", "error": f"dataset id not found: {dataset_id}"}

    selected = dict(item)
    artifacts = item.get("artifacts") or []
    if artifact_id is not None:
        if not isinstance(artifacts, list):
            return {
                "status": "FAIL",
                "error": f"dataset {dataset_id} has no artifact registry",
            }
        artifact = next(
            (a for a in artifacts if str(a.get("id")) == str(artifact_id)), None
        )
        if not artifact:
            return {
                "status": "FAIL",
                "error": f"artifact id not found: {artifact_id}",
                "dataset_id": dataset_id,
            }
        selected.update({"selected_artifact": artifact_id, **artifact})
    elif artifacts:
        if len(artifacts) == 1:
            selected.update(
                {"selected_artifact": str(artifacts[0].get("id")), **artifacts[0]}
            )
        else:
            return {
                "status": "FAIL",
                "error": "dataset publishes multiple artifacts; select one with --artifact",
                "dataset_id": dataset_id,
                "artifact_ids": [str(a.get("id")) for a in artifacts],
            }

    url = (
        selected.get("download_url")
        or selected.get("download_url")
        or selected.get("url")
    )

    if artifact_id is not None and selected.get("kind"):
        url = selected.get("url") or selected.get("download_url")
    if not url or not str(url).startswith(("http://", "https://")):
        return {
            "status": "FAIL",
            "error": "selected registry item has no direct HTTP(S) download URL",
            "dataset_id": dataset_id,
            "artifact_id": artifact_id,
            "dataset": item,
        }
    expected_sha = selected.get("sha256")
    if not expected_sha:
        return {
            "status": "FAIL",
            "error": "selected dataset artifact has no sha256; refusing unpinned acquisition",
            "dataset_id": dataset_id,
            "artifact_id": artifact_id,
        }

    if max_bytes == 8 * 1024**3:
        result = fetch(str(url), out, str(expected_sha), timeout, resume)
    else:
        result = fetch(
            str(url), out, str(expected_sha), timeout, resume, max_bytes=max_bytes
        )
    record = {
        "schema_version": SCHEMA_VERSION,
        "format": "evidencelab-acquisition-record",
        "dataset_id": dataset_id,
        "artifact_id": artifact_id or selected.get("selected_artifact"),
        "registry": str(Path(registry_path).resolve()),
        "registry_entry": item,
        "selected_item": selected,
        "result": result,
        "reproducibility": {
            "url": str(url),
            "expected_sha256": str(expected_sha),
            "resume": bool(resume),
            "timeout_seconds": int(timeout),
            "max_bytes": max_bytes,
        },
    }
    write_acquisition_record(str(Path(out).resolve()) + ".acquisition.json", record)
    result["acquisition_record"] = str(Path(out).resolve()) + ".acquisition.json"
    return result
