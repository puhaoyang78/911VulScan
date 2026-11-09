"""Python/Node/Go 的崩溃也要记成“已捕获崩溃”，不能一律算测试出错。"""
import json

from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.result_collector import collect_result


def _execution(exit_code, stderr, stdout=None):
    execution = DockerExecutionResult()
    execution.exit_code = exit_code
    execution.stderr = stderr
    execution.stdout = (json.dumps({
        "status": "NOT_REPRODUCED", "details": "stale", "evidence": [],
    }) if stdout is None else stdout)
    return execution


def _collect(execution):
    return collect_result(
        {"id": "VULN-001"},
        {"test_script": "x", "dockerfile": "x"},
        execution,
    )


def test_python_fatal_signal_is_a_crash():
    result = _collect(_execution(139, "Fatal Python error: Segmentation fault\n"))
    assert result.status == "INCONCLUSIVE"
    assert result.crash["detected"] is True
    assert result.crash["signal"] == "SIGSEGV"
    assert "已捕获崩溃" in result.details
    assert result.status != "NOT_REPRODUCED"


def test_node_out_of_memory_is_a_crash():
    result = _collect(_execution(
        134, "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory\n"))
    assert result.status == "INCONCLUSIVE"
    assert result.crash["signal"] == "SIGABRT"
    assert result.diagnostic_class == "signal:abort"


def test_go_panic_is_a_runtime_crash():
    result = _collect(_execution(2, "panic: runtime error: index out of range [5] with length 3\n"))
    assert result.status == "INCONCLUSIVE"
    assert result.diagnostic_class == "runtime:fatal"
    assert result.terminal_reason == "crash_signal"


def test_crash_without_json_is_still_a_crash():
    result = _collect(_execution(
        139, "Fatal Python error: Segmentation fault\n", stdout="no json here\n"))
    assert result.status == "INCONCLUSIVE"
    assert result.crash["detected"] is True
    assert "已捕获崩溃" in result.details


def test_python_normal_exception_is_still_a_test_error():
    result = _collect(_execution(
        1, "Traceback (most recent call last):\nValueError: bad input\n"))
    assert result.status == "ERROR"


def test_clean_exit_still_reports_not_reproduced():
    output = json.dumps({"status": "NOT_REPRODUCED", "details": "ok", "evidence": []})
    result = _collect(_execution(0, "", output))
    assert result.status == "NOT_REPRODUCED"
