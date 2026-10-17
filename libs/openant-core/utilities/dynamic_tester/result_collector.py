"""Parse container output and classify dynamic test results.

Each test container is expected to print a single JSON object to stdout:
{
    "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
    "details": "Human-readable explanation",
    "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]
}
"""

import json

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence, VALID_STATUSES
from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.diagnostics import bounded_diagnostic


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
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            generation_cost_usd=generation_cost,
        )

    if getattr(execution, "execution_error", None):
        return DynamicTestResult(
            finding_id=finding_id, identity_key=identity_key, status="ERROR",
            details=bounded_diagnostic(execution.execution_error, 2000),
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds, generation_cost_usd=generation_cost,
        )

    # Build failure
    if execution.build_error:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details=f"Docker 构建失败： {bounded_diagnostic(execution.build_error, 2000)}",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
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
            evidence=[TestEvidence(type="command_output", content=bounded_diagnostic(
                "\n".join(part for part in (execution.stdout, execution.stderr) if part), 5000))]
                if execution.stdout or execution.stderr else [],
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Parse stdout for the JSON result
    parsed = _parse_container_output(execution.stdout)

    if parsed is None:
        return DynamicTestResult(
            finding_id=finding_id,
            identity_key=identity_key,
            status="ERROR",
            details=f"容器未输出有效 JSON 结果。"
                    f"退出码：{execution.exit_code}。"
                    f"标准错误：{bounded_diagnostic(execution.stderr, 300)}",
            evidence=[TestEvidence(type="command_output", content=bounded_diagnostic(execution.stdout, 5000))],
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Valid JSON output
    status = parsed.get("status", "ERROR")
    if status not in VALID_STATUSES:
        status = "INCONCLUSIVE"
    details = parsed.get("details", "")
    if execution.exit_code != 0:
        # A stale/synthetic JSON line printed before a crash is not a successful
        # test. The trusted C runner exits 0 only after capturing sanitizer proof.
        status = "ERROR"
        details = f"容器异常退出（退出码 {execution.exit_code}），不能采信其结果。{bounded_diagnostic(execution.stderr, 300)}"

    if status == "ERROR":
        details = bounded_diagnostic(details, 2000)

    evidence = []
    for e in (parsed.get("evidence") or []):
        if isinstance(e, dict) and isinstance(e.get("type"), str) and isinstance(e.get("content"), str):
            evidence.append(TestEvidence(type=e["type"], content=(bounded_diagnostic(e["content"], 5000)
                if status == "ERROR" else e["content"][:5000])))

    if status == "CONFIRMED" and not any(e.type.strip() and e.content.strip() for e in evidence):
        status = "INCONCLUSIVE"
        details = "测试声称已确认，但未提供有效证据，无法确认漏洞。"

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
        test_code=generation.get("test_script", ""),
        dockerfile=generation.get("dockerfile", ""),
        docker_compose=generation.get("docker_compose", ""),
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
