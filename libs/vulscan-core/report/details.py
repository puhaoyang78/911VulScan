"""Read-only, deterministic presentation of existing finding records.

This module never calls a model, reads scanned source paths, or runs a PoC.
Missing old fields stay missing; display layers provide the missing-data label.
"""

import json
import sys
from pathlib import Path

from utilities.file_io import read_json


def report_text(value) -> str:
    """Keep strings verbatim and make non-string model output display-safe."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(report_text(item) for item in value)
    return json.dumps(value, ensure_ascii=False)


def finding_fields(result: dict, source_code="") -> dict:
    """Project both legacy nested findings and current flat analysis records."""
    vulns = result.get("vulnerabilities")
    vuln = next((v for v in vulns if isinstance(v, dict)), {}) if isinstance(vulns, list) else {}

    verification = result.get("verification")
    verification = verification if isinstance(verification, dict) else {}
    revised = (
        verification.get("agree") is False and not verification.get("incomplete")
    ) or bool(result.get("consistency_update"))

    def value(key, fallback=""):
        if key in ("description", "impact", "remediation", "suggested_fix"):
            if not verification.get("incomplete") and not result.get("consistency_update"):
                if key in verification:
                    return report_text(verification[key])
            if revised:
                # A corrected verdict/CWE cannot inherit a fix for the old bug.
                return report_text(verification.get("explanation")) if key == "description" else ""
        return report_text(result.get(key) or vuln.get(key) or fallback)

    if verification.get("incomplete"):
        status = "第 2 阶段未完成，尚未确认；需要人工复核。"
    elif verification.get("agree") is True:
        status = "第 2 阶段模型复核同意；不等于 PoC 已执行或崩溃已复现。"
    elif verification:
        status = "第 2 阶段模型复核已调整判定；以最终判定及解释为准，不等于动态验证。"
    else:
        status = "未记录第 2 阶段复核；当前是静态分析结果，不等于动态验证。"
    explanation = report_text(verification.get("explanation"))
    if explanation:
        status += "\n" + explanation
    if result.get("consistency_update"):
        status += "\n一致性更新（上方解释可能早于此更新）：\n" + report_text(result["consistency_update"])
    return {
        "description": value("description", result.get("reasoning")),
        "cwe_id": value("cwe_id"),
        "cwe_name": value("cwe_name"),
        "impact": value("impact"),
        "remediation": value("remediation"),
        # Dataset/code_by_route is a recorded source, not a model rewrite.
        "vulnerable_code": report_text(source_code) or value("vulnerable_code"),
        "suggested_fix": value("suggested_fix"),
        "steps_to_reproduce": value("steps_to_reproduce"),
        "stage2_verification": status,
    }


def load_dynamic_by_route(results_path: str) -> dict:
    """Join existing dynamic records only when stable identities agree.

    Positional VULN IDs alone are insufficient: old files often survive a rescan.
    Match the same way as the disclosure merge, never manufacture evidence.
    """
    directory = Path(results_path).parent
    dynamic_path = directory / "dynamic_test_results.json"
    pipeline_path = directory / "pipeline_output.json"
    if not dynamic_path.exists() or not pipeline_path.exists():
        return {}
    try:
        dynamic = read_json(dynamic_path)
        pipeline = read_json(pipeline_path)
    except (OSError, ValueError) as exc:
        # Sidecars are optional: a partial write must not destroy a valid
        # static report. Do not attach an unverified or partially read receipt.
        print(f"[报告] 动态证据未关联：无法读取可选结果文件（{type(exc).__name__}）。",
              file=sys.stderr)
        return {}
    if not isinstance(dynamic, dict) or not isinstance(pipeline, dict):
        return {}
    findings = pipeline.get("findings")
    records = dynamic.get("results")
    if not isinstance(findings, list) or not isinstance(records, list):
        return {}
    by_id = {
        f.get("id"): f for f in findings
        if isinstance(f, dict) and isinstance(f.get("id"), str)
    }
    joined = {}
    from utilities.dynamic_tester.models import VALID_STATUSES
    for record in records:
        if not isinstance(record, dict):
            continue
        fid = record.get("finding_id")
        finding = by_id.get(fid) if isinstance(fid, str) else None
        if not finding or not finding.get("identity_key"):
            continue
        if finding["identity_key"] != record.get("identity_key"):
            continue
        loc = finding.get("location")
        if not isinstance(loc, dict):
            continue
        file, function = loc.get("file"), loc.get("function")
        if not isinstance(file, str) or not isinstance(function, str):
            continue
        record = dict(record)
        if not isinstance(record.get("status"), str) or record["status"] not in VALID_STATUSES:
            record["status"] = "UNKNOWN"
        joined[f"{file}:{function}"] = record
    return joined


def dynamic_for_result(result: dict, by_route: dict) -> dict:
    """Also bind joined evidence to the current result, not a stale pipeline."""
    route = result.get("route_key") or result.get("unit_id") or ""
    record = by_route.get(route)
    if not record or ":" not in route:
        return {}
    from core.reporter import finding_identity_key
    file, function = route.split(":", 1)
    fields = finding_fields(result)
    # An absent CWE cannot authenticate a result from a different scan.
    try:
        cwe = int(fields["cwe_id"])
    except (TypeError, ValueError):
        return {}
    if cwe <= 0:
        return {}
    if finding_identity_key(file, function, cwe) != record.get("identity_key"):
        return {}
    return record
