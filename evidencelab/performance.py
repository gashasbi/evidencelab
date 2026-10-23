from __future__ import annotations
from . import SCHEMA_VERSION
from pathlib import Path
from typing import Any
import json, statistics, time, os, math, multiprocessing

from .models import Graph
from .spec import Pattern
from .parsers import parse_graph
from .matcher import Matcher
from .evaluator import _safe_case_path


def _rss_bytes_current() -> int | None:
    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        import platform

        return int(value if platform.system() == "Darwin" else value * 1024)
    except Exception:
        return None


def _set_child_limits(
    max_case_seconds: float | None, max_case_memory_bytes: int | None
) -> None:
    try:
        import resource
    except ImportError:
        return
    if max_case_memory_bytes:
        limit = int(max_case_memory_bytes)
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    if max_case_seconds and hasattr(resource, "RLIMIT_CPU"):
        cpu = max(1, int(math.ceil(float(max_case_seconds))))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))


def _performance_worker(
    conn: Any,
    manifest: str,
    pattern: Pattern,
    case: dict[str, Any],
    max_case_seconds: float | None,
    max_case_memory_bytes: int | None,
) -> None:
    started = time.perf_counter()
    try:
        _set_child_limits(max_case_seconds, max_case_memory_bytes)
        mp = Path(manifest).resolve()
        graph_path = _safe_case_path(mp, str(case["graph"]))
        graph = parse_graph(graph_path)
        result = Matcher(graph).run(pattern)
        elapsed = time.perf_counter() - started
        conn.send(
            {
                "status": result.status,
                "seconds": elapsed,
                "peak_rss_bytes": _rss_bytes_current(),
                "error": None,
            }
        )
    except MemoryError:
        conn.send(
            {
                "status": "MEMORY_LIMIT",
                "seconds": time.perf_counter() - started,
                "peak_rss_bytes": _rss_bytes_current(),
                "error": "MemoryError",
            }
        )
    except Exception as exc:
        try:
            conn.send(
                {
                    "status": "INFRA_ERROR",
                    "seconds": time.perf_counter() - started,
                    "peak_rss_bytes": _rss_bytes_current(),
                    "error": str(exc),
                }
            )
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _run_isolated_case(
    manifest: Path,
    pattern: Pattern,
    case: dict[str, Any],
    max_case_seconds: float | None,
    max_case_memory_bytes: int | None,
) -> dict[str, Any]:
    methods = multiprocessing.get_all_start_methods()
    method = "spawn" if "spawn" in methods else "fork"
    ctx = multiprocessing.get_context(method)
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_performance_worker,
        args=(
            child_conn,
            str(manifest),
            pattern,
            case,
            max_case_seconds,
            max_case_memory_bytes,
        ),
    )
    wall_started = time.perf_counter()
    proc.start()
    timeout = (float(max_case_seconds) + 1.0) if max_case_seconds else None
    proc.join(timeout)
    elapsed = time.perf_counter() - wall_started
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive() and hasattr(proc, "kill"):
            proc.kill()
            proc.join(2)
        try:
            parent_conn.close()
        except Exception:
            pass
        return {
            "status": "TIMEOUT",
            "seconds": elapsed,
            "peak_rss_bytes": None,
            "error": f"case exceeded wall-clock limit: {max_case_seconds}s",
            "time_limit_exceeded": True,
            "memory_limit_exceeded": False,
        }
    try:
        result = (
            parent_conn.recv()
            if parent_conn.poll(0.5)
            else {
                "status": "INFRA_ERROR",
                "seconds": elapsed,
                "peak_rss_bytes": None,
                "error": f"worker exited with code {proc.exitcode} without a result",
            }
        )
    except (EOFError, OSError):
        result = {
            "status": "INFRA_ERROR",
            "seconds": elapsed,
            "peak_rss_bytes": None,
            "error": f"worker exited with code {proc.exitcode} without a result",
        }
    finally:
        try:
            parent_conn.close()
        except Exception:
            pass
        try:
            child_conn.close()
        except Exception:
            pass
    peak = result.get("peak_rss_bytes")
    if result.get("status") == "MEMORY_LIMIT":
        result["memory_limit_exceeded"] = True

    memory_exceeded = result.get("status") == "MEMORY_LIMIT"
    time_exceeded = result.get("status") == "TIMEOUT" or (
        max_case_seconds is not None
        and float(result.get("seconds", elapsed)) > float(max_case_seconds)
    )
    return {
        **result,
        "seconds": float(result.get("seconds", elapsed)),
        "time_limit_exceeded": bool(time_exceeded),
        "memory_limit_exceeded": bool(memory_exceeded),
        "wall_seconds": elapsed,
    }


def profile_pattern(
    manifest: str | Path,
    pattern: Pattern,
    repeats: int = 1,
    partition: str | None = None,
    max_case_seconds: float | None = None,
    max_case_memory_bytes: int | None = None,
    isolate_cases: bool = True,
) -> dict[str, Any]:
    """Profile cases with enforceable per-case resource limits.

    Each measured case executes once per repeat. Resource exhaustion is a first-class
    outcome and never silently becomes a normal matcher result.
    """
    mp = Path(manifest).resolve()
    raw = json.loads(mp.read_text(encoding="utf-8"))
    cases = [
        c
        for c in raw.get("cases", [])
        if isinstance(c, dict)
        and (not partition or c.get("partition", "public") == partition)
    ]
    if not cases:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "FAIL",
            "repeats": max(1, repeats),
            "cases": 0,
            "error": "no cases selected",
        }

    repeats = max(1, int(repeats))
    totals: list[float] = []
    case_results: list[dict[str, Any]] = []
    violations: set[str] = set()
    infra_errors = 0

    for repeat in range(repeats):
        started = time.perf_counter()
        repeat_results = []
        for case in cases:
            cid = str(case.get("id"))
            if isolate_cases:
                result = _run_isolated_case(
                    mp, pattern, case, max_case_seconds, max_case_memory_bytes
                )
            else:
                t0 = time.perf_counter()
                try:
                    graph = parse_graph(_safe_case_path(mp, str(case["graph"])))
                    selected = Matcher(graph).run(pattern)
                    result = {
                        "status": selected.status,
                        "seconds": time.perf_counter() - t0,
                        "peak_rss_bytes": _rss_bytes_current(),
                        "error": None,
                    }
                except Exception as exc:
                    result = {
                        "status": "INFRA_ERROR",
                        "seconds": time.perf_counter() - t0,
                        "peak_rss_bytes": _rss_bytes_current(),
                        "error": str(exc),
                    }
            rr = {
                "id": cid,
                "seconds": float(result.get("seconds", 0.0)),
                "status": str(result.get("status", "INFRA_ERROR")),
                "memory_bytes": result.get("peak_rss_bytes"),
                "over_limit": bool(
                    result.get("time_limit_exceeded")
                    or result.get("memory_limit_exceeded")
                ),
                "time_limit_exceeded": bool(result.get("time_limit_exceeded")),
                "memory_limit_exceeded": bool(result.get("memory_limit_exceeded")),
                "error": result.get("error"),
                "repeat": repeat,
            }
            repeat_results.append(rr)
            if rr["over_limit"]:
                violations.add(cid)
            if rr["status"] in {"INFRA_ERROR", "MEMORY_LIMIT", "TIMEOUT"}:
                infra_errors += 1
        totals.append(time.perf_counter() - started)
        if repeat == 0:
            case_results = repeat_results

    all_case_times = sorted(float(x["seconds"]) for x in case_results)
    values = sorted(totals)

    def pct(values: list[float], quantile: float) -> float | None:
        if not values:
            return None
        return values[min(len(values) - 1, int(round((len(values) - 1) * quantile)))]

    observed_memory = max(
        (
            int(x["memory_bytes"])
            for x in case_results
            if x.get("memory_bytes") is not None
        ),
        default=None,
    )
    status = "PASS" if not violations and infra_errors == 0 else "FAIL"
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "repeats": repeats,
        "cases": len(cases),
        "isolation": {
            "enabled": bool(isolate_cases),
            "method": "spawn per case"
            if isolate_cases and "spawn" in multiprocessing.get_all_start_methods()
            else ("fork per case" if isolate_cases else "inline"),
        },
        "total_seconds": {
            "min": min(values),
            "median": statistics.median(values),
            "p95": pct(values, 0.95),
            "p99": pct(values, 0.99),
            "max": max(values),
        },
        "case_seconds": {
            "median": statistics.median(all_case_times) if all_case_times else None,
            "p95": pct(all_case_times, 0.95),
            "p99": pct(all_case_times, 0.99),
            "max": max(all_case_times, default=None),
        },
        "resource": {
            "max_case_peak_rss_bytes": observed_memory,
            "configured_max_case_memory_bytes": max_case_memory_bytes,
            "max_case_memory_bytes": max_case_memory_bytes,
            "peak_rss_is_observed": True,
        },
        "limits": {
            "max_case_seconds": max_case_seconds,
            "max_case_memory_bytes": max_case_memory_bytes,
            "violations": sorted(violations),
            "infra_errors": infra_errors,
        },
        "search_cost": {
            "case_count": len(case_results),
            "total_case_seconds": sum(all_case_times),
            "mean_case_seconds": statistics.mean(all_case_times)
            if all_case_times
            else None,
        },
        "case_results": case_results,
    }
