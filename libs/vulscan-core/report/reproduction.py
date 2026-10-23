"""Read-only rendering of persisted dynamic-test artifacts and observations.

Nothing in this module executes a PoC, infers success from a crash, or creates
build/trigger commands. Older artifacts remain readable without inventing the
missing execution record.
"""

import json
import re
import shlex

from report.localization import display_label


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
    lines = [
        "### PoC 构建、触发与验证记录", "",
        "以下内容仅整理已有测试产物和执行记录，不重新运行测试，也不生成新的攻击步骤。", "",
        "#### 预期行为与判定边界", "",
        "预期行为、测试断言和静态分析不是实测证据。崩溃类漏洞应核对目标位置、"
        "sanitizer/调用栈及异常终止；非崩溃类漏洞应核对越权响应、文件内容或其他实际安全影响。"
        "单独的非零退出码不能确认漏洞；正常退出也不能证明安全或已修复。", "",
    ]
    if reproduction.get("capture_error"):
        lines += ["产物记录限制：", fenced(reproduction["capture_error"]), ""]
    if record.get("expected_behavior"):
        lines += ["原记录中的预期（非观察结果）：", fenced(record["expected_behavior"]), ""]
    lines += ["#### 构建与触发步骤", ""]
    if artifacts:
        lines += ["1. 将下列**实际暂存产物**按记录的相对文件名恢复至独立测试目录。", ""]
        source = reproduction.get("source")
        if isinstance(source, dict) and source:
            lines += ["2. 使用本次扫描对应提交的原始目标文件；恢复前核对以下文件名和 SHA-256：",
                      fenced(source, "json"), ""]
        else:
            lines += ["2. 目标源文件及版本未完整记录，复现前需人工补全，不能假定测试环境已可重建。", ""]
        lines += ["3. 下方按顺序保留构建/运行命令。原 cwd 是已清理的临时目录；"
                  "复现时使用恢复后的测试目录，并保留记录中的隔离限制。"
                  "运行命令通过 Dockerfile / Compose 的入口触发下列 PoC，具体输入见测试源码。", ""]
    else:
        lines += ["未记录完整实际暂存文件；以下生成稿不能保证与当时执行配置一致。"
                  "尤其 Compose 会经过隔离配置处理，不能直接把原始生成稿视作已执行配置。", ""]
    if commands:
        stage_labels = {"build": "构建", "run": "运行/触发", "start": "启动服务", "observe": "收集日志"}
        for index, command in enumerate(commands, 1):
            argv = command.get("argv")
            stage = command.get("stage")
            label = stage_labels.get(stage, "执行") if isinstance(stage, str) else "执行"
            lines += [f"**记录命令 {index}：{label}**", ""]
            if isinstance(argv, list) and all(isinstance(arg, str) for arg in argv):
                lines += [fenced(shlex.join(argv), "sh")]
            else:
                lines += ["命令参数未记录或格式无效。"]
            if command.get("cwd"):
                lines += ["原工作目录：", fenced(command["cwd"])]
            lines += [""]
    else:
        lines += ["构建/运行命令未记录；报告不猜测可执行命令，也不声称已完成复现。", ""]
    lines += ["#### 已观察结果（原记录）", "",
              f"动态结果状态：{display_label(status)}", ""]
    if record.get("details"):
        lines += ["结果说明（测试记录，不是额外独立验证）：", fenced(record["details"]), ""]
    if commands:
        lines += ["命令日志按现有诊断规则脱敏并限长；截断时保留开头和末尾，正文含截断标记。", ""]
    for index, command in enumerate(commands, 1):
        code = command.get("exit_code")
        code_text = str(code) if isinstance(code, int) and not isinstance(code, bool) else "未记录"
        timed_out = command.get("timed_out")
        timeout_text = "是" if timed_out is True else "否" if timed_out is False else "未记录"
        lines += [f"**命令 {index}：退出码 {code_text}；超时：{timeout_text}**",
                  "这是对应宿主侧 Docker 命令的退出状态，不等同于目标进程退出状态；"
                  "特别是日志命令退出成功不代表容器或目标执行成功。", ""]
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
            lines += [f"**证据 {index}（测试产出：{label}）**",
                      "原始类型：", fenced(item.get("type")),
                      "原始内容：", fenced(item.get("content")), ""]
    else:
        lines += ["未记录有效证据；不得仅凭状态标签声称已观察到崩溃或安全影响。", ""]
    if not commands:
        lines += ["未保留命令级退出状态、标准输出和标准错误；现有证据不包含这些字段时，不能补写。", ""]
    lines += ["#### 留存的 PoC 与构建文件", ""]
    if artifacts:
        for artifact in artifacts:
            lines += ["文件名：", fenced(artifact.get("filename", "未记录")),
                      "实际暂存内容：", fenced(artifact.get("content", "")), ""]
    else:
        for key, label in (("test_code", "原始生成的测试源码（文件名未记录）"),
                           ("dockerfile", "原始生成的 Dockerfile"),
                           ("docker_compose", "原始生成的 Compose（非实际执行配置）")):
            if isinstance(record.get(key), str) and record[key]:
                lines += [label + "：", fenced(record[key]), ""]
        if not any(record.get(key) for key in ("test_code", "dockerfile", "docker_compose")):
            lines += ["未保存 PoC / 构建文件。", ""]
    return "\n".join(lines).rstrip() + "\n"
