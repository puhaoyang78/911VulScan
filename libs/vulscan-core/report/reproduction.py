"""Readable PoC explanations from saved results, without executing or rewriting code."""

import json
import re
from pathlib import PurePosixPath

from core.language_registry import fence_for_path


def fenced(value, language: str = "text") -> str:
    """Keep untrusted code inside a fence, including embedded backticks."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}"


def _records(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _paragraph(value) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def result_summary(record: dict) -> str:
    """Show the recorded conclusion, without embedding a build/runtime transcript."""
    details = record.get("details")
    if not isinstance(details, str) or not details.strip():
        return "未记录具体观察结果。"
    line = details.strip().splitlines()[0]
    for cause in ("Docker 构建超时", "Docker 构建失败", "Docker 环境不可用",
                  "Docker 基础镜像不可用", "容器执行失败", "容器执行超时"):
        if line.startswith(cause):
            return cause + "。"
    line = re.split(r"标准错误[：:]|标准输出[：:]", line, maxsplit=1)[0]
    return line[:500] + ("…" if len(line) > 500 else "")


def render_reproduction(record: dict, finding: dict | None = None) -> str:
    """Explain the test first, then show complete, actually staged PoC files.

    Commands and raw observations remain in the result JSON, outside the report.
    A generated draft is explicitly distinguished from the saved execution files.
    """
    if not isinstance(record, dict):
        return ""
    finding = finding if isinstance(finding, dict) else {}
    reproduction = record.get("reproduction")
    reproduction = reproduction if isinstance(reproduction, dict) else {}
    artifacts = _records(reproduction.get("artifacts"))
    raw_status = record.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status in {
        "CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"
    } else "UNKNOWN"
    explanation = _paragraph(record.get("poc_summary"))
    if not explanation:
        explanation = _paragraph(finding.get("description"))
        # Legacy steps may append stale verification notes after the design.
        steps = finding.get("steps_to_reproduce") or record.get("steps_to_reproduce")
        steps = _paragraph(re.split(r"\n\s*\n", steps, maxsplit=1)[0]) if isinstance(steps, str) else ""
        if steps:
            explanation += "\n\nPoC 构造思路（静态分析）：" + steps
        else:
            explanation += "\n\n旧记录未保存 PoC 构造说明。"

    outcomes = {
        "CONFIRMED": "动态测试已复现该问题。",
        "NOT_REPRODUCED": "本次动态测试未复现该问题。",
        "BLOCKED": "动态测试受阻，尚未验证该问题。",
        "INCONCLUSIVE": "本次动态测试无法确定是否复现。",
        "ERROR": "动态测试未能完成，不能据此确认复现。",
        "SKIPPED": "本次未执行动态测试。",
        "UNKNOWN": "动态测试结论未知。",
    }
    lines = ["### PoC 与验证说明", "", explanation.strip(), "",
             outcomes[status] + result_summary(record), ""]
    if status == "CONFIRMED" and not _records(reproduction.get("commands")):
        lines += ["旧记录缺少执行记录，无法还原当时的验证过程。", ""]
    if reproduction.get("capture_error"):
        lines += ["测试产物保存不完整。", ""]

    # Keep inputs and helper scripts as well as the main PoC; omit build setup.
    setup_names = {"dockerfile", "docker-compose.yml", "docker-compose.yaml",
                   "compose.yml", "compose.yaml", "requirements.txt", "package.json",
                   "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum",
                   "_vulscan_c_runner.py", "_vulscan_c_spec.json"}
    files = [item for item in artifacts if isinstance(item.get("filename"), str)
             and PurePosixPath(item["filename"]).name.lower() not in setup_names
             and isinstance(item.get("content"), str) and item["content"]]
    if files:
        for item in files:
            lines += [f"`{_paragraph(item['filename'])}`", "",
                      fenced(item["content"], fence_for_path(item["filename"]) or "text"), ""]
    elif isinstance(record.get("test_code"), str) and record["test_code"]:
        lines += ["PoC 生成稿，未保存执行版本。", "",
                  fenced(record["test_code"]), ""]
    else:
        lines += ["未保存 PoC 源码。", ""]
    return "\n".join(lines).rstrip() + "\n"
