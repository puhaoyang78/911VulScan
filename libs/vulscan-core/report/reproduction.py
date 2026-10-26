"""Read-only rendering of persisted dynamic-test artifacts and observations.

Nothing in this module executes a PoC, infers success from a crash, or creates
build/trigger commands. Older artifacts remain readable without inventing the
missing execution record.
"""

import json
import re
import shlex

from report.localization import display_label, dynamic_label


def fenced(value, language: str = "text") -> str:
    """Keep untrusted code/logs inside a fence, including embedded backticks."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}"


def _records(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def render_reproduction(record: dict) -> str:
    """Render a result or identity-checked dynamic_testing block as Markdown."""
    if not isinstance(record, dict):
        return ""
    reproduction = record.get("reproduction")
    reproduction = reproduction if isinstance(reproduction, dict) else {}
    commands = _records(reproduction.get("commands"))
    artifacts = _records(reproduction.get("artifacts"))
    raw_status = record.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status in {
        "CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"
    } else "UNKNOWN"
    lines = ["### PoC 与测试记录", "", f"动态测试：{dynamic_label(status)}", ""]
    if reproduction.get("capture_error"):
        lines += ["记录不完整：", fenced(reproduction["capture_error"]), ""]
    if record.get("expected_behavior"):
        lines += ["#### 预期行为（非实测）", "", fenced(record["expected_behavior"]), ""]
    lines += ["#### 复现准备", ""]
    if artifacts:
        lines += ["1. 按下方文件名恢复测试与构建文件。", ""]
        source = reproduction.get("source")
        if isinstance(source, dict) and source:
            lines += ["2. 准备对应提交的目标文件，核对文件名和 SHA-256：",
                      fenced(source, "json"), ""]
        else:
            lines += ["2. 目标源文件或版本未完整记录，复现前需补全。", ""]
        if commands:
            lines += ["3. 在恢复后的测试目录依次运行下方命令，保留 Docker 隔离参数。"
                      "原工作目录为已清理的临时路径。", ""]
    else:
        lines += ["未保存实际执行的文件；下方生成稿可能与执行版本不同。", ""]
    lines += ["#### 构建与运行命令", ""]
    if commands:
        stage_labels = {"build": "构建", "run": "运行", "start": "启动服务", "observe": "收集日志", "cleanup": "清理"}
        for index, command in enumerate(commands, 1):
            argv = command.get("argv")
            stage = command.get("stage")
            label = stage_labels.get(stage, "执行") if isinstance(stage, str) else "执行"
            lines += [f"**命令 {index}：{label}**", ""]
            if isinstance(argv, list) and all(isinstance(arg, str) for arg in argv):
                lines += [fenced(shlex.join(argv), "sh")]
            else:
                lines += ["命令参数未记录或格式无效。"]
            if command.get("cwd"):
                lines += ["原工作目录：", fenced(command["cwd"])]
            lines += [""]
    else:
        lines += ["构建/运行命令未记录。", ""]
    lines += ["#### 实际结果", ""]
    if record.get("details"):
        lines += ["结果说明：", fenced(record["details"]), ""]
    if any(command.get("stage") == "observe" for command in commands):
        lines += ["日志命令的退出码仅表示日志读取状态。", ""]
    for index, command in enumerate(commands, 1):
        code = command.get("exit_code")
        code_text = str(code) if isinstance(code, int) and not isinstance(code, bool) else "未记录"
        timed_out = command.get("timed_out")
        timeout_text = "是" if timed_out is True else "否" if timed_out is False else "未记录"
        lines += [f"**命令 {index}：Docker 退出码 {code_text}；超时：{timeout_text}**", ""]
        for field, title in (("stdout", "标准输出"), ("stderr", "标准错误")):
            content = command.get(field)
            rendered = (fenced(content) if content else "（空输出）") if isinstance(content, str) else "未记录输出。"
            lines += [f"{title}：", rendered, ""]
    evidence = _records(record.get("evidence"))
    if evidence:
        for index, item in enumerate(evidence, 1):
            kind = item.get("type")
            label = display_label(kind) if isinstance(kind, str) and kind in {
                "file_read", "http_response", "command_output", "network_capture"
            } else "其他"
            lines += [f"**测试输出 {index}（类型：{label}）**",
                      "原始类型：", fenced(item.get("type")),
                      "原始内容：", fenced(item.get("content")), ""]
    else:
        lines += ["未记录测试输出。", ""]
    if not commands:
        lines += ["未记录命令退出码、标准输出和标准错误。", ""]
    lines += ["#### 测试与构建文件", ""]
    if artifacts:
        for artifact in artifacts:
            lines += ["文件名：", fenced(artifact.get("filename", "未记录")),
                      "执行时的文件内容：", fenced(artifact.get("content", "")), ""]
    else:
        for key, label in (("test_code", "原始生成的测试源码（文件名未记录）"),
                           ("dockerfile", "原始生成的 Dockerfile"),
                           ("docker_compose", "原始生成的 Compose（非实际执行配置）")):
            if isinstance(record.get(key), str) and record[key]:
                lines += [label + "：", fenced(record[key]), ""]
        if not any(record.get(key) for key in ("test_code", "dockerfile", "docker_compose")):
            lines += ["未保存 PoC / 构建文件。", ""]
    return "\n".join(lines).rstrip() + "\n"
