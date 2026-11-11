"""Parse container output and classify dynamic test results.

Each test container is expected to print a single JSON object to stdout:
{
    "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
    "details": "Human-readable explanation",
    "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]
}
"""

import json
import re

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence, VALID_STATUSES
from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.diagnostics import bounded_diagnostic


# Docker 把信号退出码报成 128+n。这里只列常见信号。
_SIGNAL_BY_EXIT = {
    132: "SIGILL", 134: "SIGABRT", 135: "SIGBUS",
    136: "SIGFPE", 139: "SIGSEGV",
}
_FATAL_LINE = re.compile(
    r"^(?:Segmentation fault|Aborted|Bus error|Illegal instruction|"
    r"Floating point exception)(?: \(core dumped\))?$"
    r"|^Fatal Python error:"
    r"|^FATAL ERROR:"
    r"|^fatal error:"
    r"|^panic: ",
    re.M,
)


def _generic_crash(execution: DockerExecutionResult) -> dict:
    """Python/Node/Go 也可能被信号打死，不能一律当成“测试出错”。"""
    code = execution.exit_code
    signal = _SIGNAL_BY_EXIT.get(code if code >= 0 else 128 - code, "")
    text = f"{execution.stderr or ''}\n{execution.stdout or ''}"
    if signal:
        key = signal.lower().replace("sig", "")
        if key == "abrt":
            key = "abort"
        return {"detected": True, "signal": signal, "exit_code": code,
                "diagnostic_class": "signal:" + key}
    if code != 0 and _FATAL_LINE.search(text):
        return {"detected": True, "signal": "", "exit_code": code,
                "diagnostic_class": "runtime:fatal"}
    return {}


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _crash_fields(parsed: dict) -> dict:
    diagnostic = parsed.get("diagnostic_class")
    terminal = parsed.get("terminal_reason")
    return {
        "diagnostic_class": diagnostic if isinstance(diagnostic, str) else "",
        "crash": _dict(parsed.get("crash")),
        "anchor": _dict(parsed.get("anchor")),
        "terminal_reason": terminal if isinstance(terminal, str) else "",
    }


def collect_result(
    finding: dict,
    generation: dict | None,
    execution: DockerExecutionResult | None,
    generation_cost: float = 0.0,
) -> DynamicTestResult:
    """Parse container output into a DynamicTestResult.

    Args:
        finding: Original finding dict from pipeline_output.json
        generation: Test generation output (or None if generation failed)
        execution: Docker execution result (or None if not run)
        generation_cost: Cost of LLM test generation in USD

    Returns:
        DynamicTestResult with parsed status and evidence
    """
    finding_id = finding.get("id", "unknown")
    # #314: the run-stable identity (threaded from the pipeline finding)
    # so the report merge can verify the join — the positional VULN-NNN
    # is not a durable key across artifacts.
    identity_key = finding.get("identity_key", "")

    # Generation failed
    if generation is None:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details="测试生成失败：模型未返回有效测试代码",
            generation_cost_usd=generation_cost,
        )

    # Execution not attempted
    if execution is None:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details="未执行 Docker 测试",
            failure_phase="environment",
            terminal_reason="execution_not_attempted",
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            generation_cost_usd=generation_cost,
        )

    # Observational receipt from the executor; no status inference from it.
    reproduction = getattr(execution, "reproduction", {})
    reproduction = reproduction if isinstance(reproduction, dict) else {}

    if getattr(execution, "execution_error", None):
        return DynamicTestResult(
            finding_id=finding_id, identity_key=identity_key, status="ERROR",
            details=bounded_diagnostic(execution.execution_error, 2000),
            failure_phase="environment",
            terminal_reason="execution_error",
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            reproduction=reproduction,
            elapsed_seconds=execution.elapsed_seconds, generation_cost_usd=generation_cost,
        )

    # Build failure. The label comes from the executor's failure classification so
    # a build timeout is never reported as an ordinary build failure.
    if execution.build_error:
        label = getattr(execution, "failure_label", "") or "Docker 构建失败"
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details=f"{label}：{bounded_diagnostic(execution.build_error, 2000)}",
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            reproduction=reproduction,
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Timeout
    if execution.timed_out:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="INCONCLUSIVE",
            details="容器执行超时",
            failure_phase="run",
            terminal_reason="poc_timeout",
            evidence=[TestEvidence(type="command_output", content=bounded_diagnostic(
                "\n".join(part for part in (execution.stdout, execution.stderr) if part), 5000))]
                if execution.stdout or execution.stderr else [],
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            reproduction=reproduction,
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Parse stdout for the JSON result
    parsed = _parse_container_output(execution.stdout)
    generic = _generic_crash(execution)

    if parsed is None and generic:
        # 程序崩了，来不及打印 JSON；这仍然是崩溃，不是“测试出错”。
        label = generic["signal"] or "运行时错误"
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="INCONCLUSIVE",
            details=(f"已捕获崩溃（待复核）。程序因 {label} 退出"
                     f"（退出码 {execution.exit_code}），没有留下可用的诊断；"
                     "这不是未复现。"),
            failure_phase="run",
            terminal_reason="crash_signal",
            crash={"detected": True, "signal": label,
                   "exit_code": execution.exit_code},
            diagnostic_class=generic["diagnostic_class"],
            evidence=[TestEvidence(type="command_output",
                                   content=bounded_diagnostic(execution.stderr, 5000))],
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            reproduction=reproduction,
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    if parsed is None:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details=f"容器未输出有效 JSON 结果。"
                    f"退出码：{execution.exit_code}。"
                    f"标准错误：{bounded_diagnostic(execution.stderr, 300)}",
            failure_phase="run",
            terminal_reason="no_result_output",
            evidence=[TestEvidence(type="command_output", content=bounded_diagnostic(execution.stdout, 5000))],
            poc_summary=generation.get("poc_summary", ""),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            reproduction=reproduction,
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Valid JSON output
    status = parsed.get("status", "ERROR")
    if status not in VALID_STATUSES:
        status = "INCONCLUSIVE"
    details = parsed.get("details", "")
    crash_fields = _crash_fields(parsed)
    if crash_fields["crash"].get("detected"):
        # 崩了就是崩了：文案里先写清楚，不能让读者只看“无法确定”就以为没复现。
        details = "已捕获崩溃（待复核）。" + details
    if execution.exit_code != 0 and generic:
        # Python/Node/Go 被信号打死，记成崩溃，不记成测试出错。
        status = "INCONCLUSIVE"
        label = generic["signal"] or "运行时错误"
        details = (f"已捕获崩溃（待复核）。程序因 {label} 退出"
                   f"（退出码 {execution.exit_code}），但没有可关联到源码的诊断；"
                   "这不是未复现。")
        crash_fields = {
            "crash": {"detected": True, "signal": label,
                      "exit_code": execution.exit_code},
            "diagnostic_class": generic["diagnostic_class"],
            "anchor": {"kind": "unknown"},
            "terminal_reason": "crash_signal",
        }
    elif execution.exit_code != 0:
        # A stale/synthetic JSON line printed before a crash is not a successful
        # test. The trusted C runner exits 0 only after capturing sanitizer proof.
        status = "ERROR"
        details = f"容器异常退出（退出码 {execution.exit_code}），不能采信其结果。{bounded_diagnostic(execution.stderr, 300)}"
        crash_fields["terminal_reason"] = "container_nonzero_exit"

    if status == "ERROR":
        details = bounded_diagnostic(details, 2000)

    evidence = []
    for e in (parsed.get("evidence") or []):
        if isinstance(e, dict) and isinstance(e.get("type"), str) and isinstance(e.get("content"), str):
            evidence.append(TestEvidence(type=e["type"], content=(bounded_diagnostic(e["content"], 5000)
                if status == "ERROR" else e["content"][:5000])))

    if status == "CONFIRMED" and not any(e.type.strip() and e.content.strip() for e in evidence):
        status = "INCONCLUSIVE"
        details = "测试声称已复现，但未提供测试输出，无法确认漏洞。"

    # Only the fixed native runner may mark an inconclusive test as repairable.
    # Do not regenerate arbitrary NOT_REPRODUCED/BLOCKED results to seek success.
    native = generation.get("native_language") in ("c", "cpp")
    phase = parsed.get("failure_phase", "") if native else ""
    phase = phase if isinstance(phase, str) and phase in {"build", "run", "analysis", "environment"} else ""
    retryable = parsed.get("retryable") if native and type(parsed.get("retryable")) is bool else None
    if execution.exit_code != 0:
        phase, retryable = "run", (False if generic else None)

    return DynamicTestResult(
        finding_id=finding_id,
        # #314 (review blocker): the SUCCESS path — the only path a real
        # verdict (CONFIRMED/NOT_REPRODUCED/BLOCKED/INCONCLUSIVE) takes —
        # must thread the identity key like every other construction, or the
        # results file serializes keyless and the report merge abstains on
        # EVERY fresh run (the merge self-disables).
        identity_key=identity_key,
        status=status,
        details=details,
        evidence=evidence,
        poc_summary=generation.get("poc_summary", ""),
        test_code=generation.get("test_script", ""),
        dockerfile=generation.get("dockerfile", ""),
        docker_compose=generation.get("docker_compose", ""),
        reproduction=reproduction,
        failure_phase=phase,
        retryable=retryable,
        **crash_fields,
        elapsed_seconds=execution.elapsed_seconds,
        generation_cost_usd=generation_cost,
    )


def _parse_container_output(stdout: str) -> dict | None:
    """Extract the JSON result object from container stdout.

    The container may print debug info before the JSON. We look for the
    last valid JSON object in the output.
    """
    if not stdout.strip():
        return None

    def valid(obj):
        return (isinstance(obj, dict) and isinstance(obj.get("status"), str)
                and isinstance(obj.get("details", ""), str)
                and isinstance(obj.get("evidence", []), list))

    # Try parsing the entire output as JSON
    try:
        parsed = json.loads(stdout.strip())
        if valid(parsed):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try each line from the end (last JSON object wins)
    lines = stdout.strip().split("\n")
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                if valid(parsed):
                    return parsed
            except json.JSONDecodeError:
                continue

    return None
