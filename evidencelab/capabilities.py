from __future__ import annotations
from pathlib import Path
import json, re, shutil, subprocess
from typing import Any

JOERN_COMMANDS = ("joern", "joern-parse", "joern-export", "joern-slice")


def _version_from_output(text: str) -> str | None:
    for pattern in (r"Version:\s*([^\s]+)", r"version\s*[:=]\s*([^\s]+)"):
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(1)
    return None


def command_info(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    out: dict[str, Any] = {"installed": bool(path), "path": path}
    if not path:
        return out
    try:
        p = subprocess.run([path, "--help"], text=True, capture_output=True, timeout=10)
        text = p.stdout + p.stderr
        out["exit_code"] = p.returncode
        out["help_available"] = p.returncode == 0
        version = _version_from_output(text)
        if version:
            out["version"] = version
    except Exception as exc:
        out["error"] = str(exc)
    return out


def joern_version(timeout: int = 20) -> str | None:
    path = shutil.which("joern")
    if not path:
        return None
    for args in ([path, "--version"], [path, "--help"], [path]):
        try:
            if args == [path]:
                p = subprocess.run(
                    args,
                    input=":exit\n",
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                )
            else:
                p = subprocess.run(
                    args, text=True, capture_output=True, timeout=timeout
                )
            v = _version_from_output(p.stdout + p.stderr)
            if v:
                return v
        except Exception:
            continue
    return None


def detect() -> dict[str, Any]:
    return {
        "joern_version": joern_version(),
        "commands": {c: command_info(c) for c in JOERN_COMMANDS},
    }


def write_capabilities(path: str | Path) -> dict[str, Any]:
    d = Path(path)
    d.parent.mkdir(parents=True, exist_ok=True)
    payload = detect()
    d.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
