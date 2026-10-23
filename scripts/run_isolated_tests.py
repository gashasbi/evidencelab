#!/usr/bin/env python3
"""Run each pytest file in a fresh process group and clean descendants.

This is a release-verification utility, not a test framework. It prevents
cross-test process state from leaking between legacy tests and hanging the
release runner.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def kill_group(p: subprocess.Popen[object], sig: int) -> None:
    try:
        os.killpg(p.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("tests", nargs="*", help="specific pytest files")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    files = (
        [Path(x) for x in args.tests]
        if args.tests
        else sorted((root / "tests").glob("test_*.py"))
    )
    files = [((root / f) if not f.is_absolute() else f).resolve() for f in files]
    if not files:
        print("No pytest files found.", file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["EVIDENCELAB_REPO_ROOT"] = str(root.resolve())
    env["PYTHONPATH"] = str(root) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    total = 0
    started = time.monotonic()
    for index, file in enumerate(files, 1):
        print(f"[isolated {index}/{len(files)}] {file.relative_to(root)}", flush=True)
        p = subprocess.Popen(
            [sys.executable, "-m", "pytest", "-q", str(file)],
            cwd=root,
            env=env,
            start_new_session=True,
        )
        rc: int
        try:
            rc = p.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print(
                f"[isolated] TIMEOUT after {args.timeout:.0f}s: {file}",
                file=sys.stderr,
                flush=True,
            )
            kill_group(p, signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_group(p, signal.SIGKILL)
                p.wait(timeout=5)
            return 124
        finally:
            kill_group(p, signal.SIGTERM)
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                kill_group(p, signal.SIGKILL)
                p.wait(timeout=2)

        if rc != 0:
            print(f"[isolated] FAIL rc={rc}: {file}", file=sys.stderr, flush=True)
            return rc

        total += 1

    elapsed = time.monotonic() - started
    print(f"[isolated] PASS: {total} test files in {elapsed:.2f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
