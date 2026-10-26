"""Versioned, observational UI telemetry. Never used to decide scan outcomes.

The web runner supplies VULSCAN_JOB_ID only to the primary scan invocation.
One locked writer orders events from worker threads; stdout's CLI envelope and
the existing human stderr logs are unchanged. Finding identity is the recorded
route_key (one analysis finding per code unit), not the positional VULN number.
"""
import json
import math
import os
import sys
import threading
import time
from datetime import datetime, timezone

PREFIX = "@vulscan-event "
_lock = threading.RLock()
_seq = 0
_known = set()
_dynamic_states = {}
_verify = None
_dynamic = None
_test_context = threading.local()


def _bounded(value, limit=8000):
    value = str(value)
    return value if len(value) <= limit else value[:limit] + "\n[展示已截断，请查看原始结果或报告]"


def start(*, verify, dynamic):
    global _seq, _verify, _dynamic
    with _lock:
        _seq = 0
        _known.clear()
        _dynamic_states.clear()
        _verify, _dynamic = verify, dynamic
        emit("scan.started", stage="initialize", message="扫描器已启动")


def emit(kind, *, stage="", **fields):
    global _seq
    job_id = os.environ.get("VULSCAN_JOB_ID")
    if not job_id:
        return
    with _lock:
        for name in ("message", "details"):
            if name in fields:
                fields[name] = _bounded(fields[name], 16000)
        _seq += 1
        record = dict(version=1, job_id=job_id, seq=_seq, type=kind,
                      time=datetime.now(timezone.utc).isoformat(), stage=stage,
                      **fields)
        # One complete write keeps the frame intact when worker threads also
        # print ordinary diagnostics to the shared stderr stream.
        sys.stderr.write(PREFIX + json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        sys.stderr.flush()


def finding(result, *, stage="analyze", force=False, model_review=None, duration_seconds=None):
    if not os.environ.get("VULSCAN_JOB_ID") or not isinstance(result, dict):
        return
    from report.details import finding_fields, model_review_status
    route = result.get("route_key") or result.get("unit_id")
    if not isinstance(route, str) or not route:
        return  # no invented identity or positional join
    verdict = str(result.get("finding") or result.get("verdict") or "").lower()
    with _lock:
        if not (force or route in _known or verdict in ("vulnerable", "bypassable")):
            return
        _known.add(route)
        fields = finding_fields(result)
        review = model_review or model_review_status(result)
        if review == "unreviewed":
            review = "pending" if _verify else "not_requested"
        file, sep, function = route.partition(":")
        vulns = result.get("vulnerabilities")
        vuln = next((v for v in vulns if isinstance(v, dict)), {}) if isinstance(vulns, list) else {}
        title = vuln.get("name") or result.get("name") or result.get("attack_vector") or "候选问题（未提供标题）"
        severity = str(result.get("severity") or vuln.get("severity") or "").lower()
        item = dict(finding_id=route, title=_bounded(title, 2000),
                    file=file if sep else "", function=function if sep else route,
                    severity=severity if severity in ("critical", "high", "medium", "low") else "",
                    cwe=fields["cwe_id"], cwe_name=fields["cwe_name"],
                    model_review=review, verdict=verdict,
                    description=_bounded(fields["description"]),
                    review_details=_bounded(fields["stage2_verification"]))
        emit("finding.upsert", stage=stage, finding_id=route, finding=item,
             status=review,
             duration_seconds=duration_seconds,
             details=_bounded(result.get("error") or fields["stage2_verification"]) if stage == "verify" else "",
             message="更新模型复核结果" if stage == "verify" else "发现候选问题")


def pipeline_findings(findings):
    """Associate display IDs/materials with the SAME recorded route identity."""
    if not os.environ.get("VULSCAN_JOB_ID"):
        return
    for item in findings:
        loc = item.get("location") or {}
        if not isinstance(loc, dict) or not isinstance(loc.get("file"), str) or not isinstance(loc.get("function"), str) or not loc["file"] or not loc["function"]:
            continue
        route = f'{loc["file"]}:{loc["function"]}'
        projected = dict(finding_id=route, report_id=str(item.get("id") or ""),
                         title=str(item.get("name") or ""), file=loc["file"], function=loc["function"])
        if route not in _dynamic_states:
            _dynamic_states[route] = "pending" if _dynamic else "skipped"
            projected.update(dynamic=_dynamic_states[route], dynamic_details="" if _dynamic else "未启用动态测试")
        emit("finding.upsert", stage="build-output", finding_id=route, finding=projected,
             message="关联报告编号")


def dynamic(finding, result=None, *, status=None, attempt=None, phase="", execution=None):
    if not os.environ.get("VULSCAN_JOB_ID"):
        return
    loc = finding.get("location") or {}
    if not isinstance(loc, dict) or not loc.get("file") or not loc.get("function"):
        return
    route = f'{loc["file"]}:{loc["function"]}'
    if attempt is None:
        retries = getattr(result, "retry_count", 0)
        attempt = retries + 1 if type(retries) is int and retries >= 0 else 0
    _test_context.route, _test_context.attempt = route, attempt
    raw_status = status or getattr(result, "status", "UNKNOWN")
    raw_status = raw_status if isinstance(raw_status, str) else "UNKNOWN"
    status_map = {"CONFIRMED": "reproduced", "NOT_REPRODUCED": "not_reproduced",
                  "BLOCKED": "blocked", "INCONCLUSIVE": "inconclusive", "ERROR": "error",
                  "SKIPPED": "skipped", "RUNNING": "running"}
    displayed = status_map.get(raw_status, "unknown")
    if raw_status == "ERROR" and execution is not None:
        if getattr(execution, "infrastructure_error", False):
            displayed = "environment_error"
        if getattr(execution, "build_error", None):
            phase = "build"
        elif getattr(execution, "execution_error", None):
            phase = "environment" if displayed == "environment_error" else "run"
    details = getattr(result, "details", "") or ""
    duration = getattr(result, "elapsed_seconds", None)
    duration = duration if type(duration) in (int, float) and math.isfinite(duration) and duration >= 0 else None
    _dynamic_states[route] = displayed
    emit("validation.updated", stage="dynamic-test", phase=phase, finding_id=route, attempt=attempt,
         finding=dict(finding_id=route, dynamic=displayed, dynamic_details=_bounded(details),
                      attempt=attempt, failure_phase=phase if displayed in ("error", "environment_error") else ""),
         duration_seconds=duration,
         status=displayed, message="动态测试执行中" if raw_status == "RUNNING" else "动态测试结果",
         details=_bounded(details))


def command(phase, status, *, details="", duration_seconds=None):
    route = getattr(_test_context, "route", None)
    if route:
        emit("activity", stage="dynamic-test", phase=phase, status=status,
             finding_id=route, attempt=_test_context.attempt,
             message="Docker 命令" if status != "running" else "执行 Docker 命令",
             details=_bounded(details, 16000), duration_seconds=duration_seconds)


def command_output(phase):
    """Capture worker identity before pipe readers enter their own threads.

    All output reaches the raw log. Structured activity samples at most once
    every three seconds per command, keeping the persisted UI snapshot bounded.
    """
    route = getattr(_test_context, "route", None)
    attempt = getattr(_test_context, "attempt", 0)
    started, last = time.monotonic(), float("-inf")
    lock = threading.Lock()

    def observe(output):
        nonlocal last
        if not output:
            return
        with lock:
            sys.stderr.write("".join(f"[dynamic-test] [{phase}] {line}\n"
                                     for line in output.splitlines()))
            sys.stderr.flush()
            now = time.monotonic()
            if route and now - last >= 3:
                last = now
                emit("activity", stage="dynamic-test", phase=phase, status="running",
                     finding_id=route, attempt=attempt,
                     message=_bounded(output.strip().splitlines()[-1], 180),
                     details=_bounded(output, 4000),
                     duration_seconds=round(now - started, 2))
    return observe


def skipped(step, reason):
    emit("stage.changed", stage=step, status="error" if reason == "failed" else "skipped", message="阶段失败" if reason == "failed" else "跳过阶段", details=reason)
    if step == "dynamic-test" and reason != "failed":
        with _lock:
            for route in sorted(_known):
                if _dynamic_states.get(route) not in (None, "pending"):
                    continue
                _dynamic_states[route] = "skipped"
                emit("validation.updated", stage=step, finding_id=route,
                     finding=dict(finding_id=route, dynamic="skipped",
                                  dynamic_details=reason),
                     status="skipped", message="动态测试未执行", details=reason)
