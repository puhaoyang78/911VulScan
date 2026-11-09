"""C/C++ 崩溃分类：新崩溃类型、裸信号和长日志都要有明确结论。

这里只调用纯函数 classify_run，不编译、不运行 Docker、不调用模型。
"""
import json

import pytest

from utilities.dynamic_tester.docker_templates import c_runner
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester import docker_executor


TARGET = "/test/repository/main.c"
DRIVER = "/test/test_exploit.c"


def _stack_overflow(frames=2000):
    lines = [
        "AddressSanitizer:DEADLYSIGNAL",
        "=" * 65,
        "==12==ERROR: AddressSanitizer: stack-overflow on address 0x7f00",
        "    #0 0x4034c4 in process_array /test/repository/main.c:68",
        "    #1 0x4034c4 in process_value /test/repository/main.c:91",
    ]
    for i in range(2, frames):
        lines.append(f"    #{i} 0x403540 in process_array /test/repository/main.c:70")
    lines += [
        "SUMMARY: AddressSanitizer: stack-overflow ../../src/asan_thread.cpp:3 in process_array",
        "==12==ABORTING",
    ]
    return "\n".join(lines) + "\n"


def test_stack_overflow_is_confirmed_when_target_frame_present():
    result = c_runner.classify_run("", _stack_overflow(), -6,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "CONFIRMED", result
    assert result["diagnostic_class"] == "asan:stack-overflow"
    assert result["anchor"]["kind"] == "target"
    assert result["terminal_reason"] == "sanitizer_fault"


def test_new_asan_kind_is_not_ignored():
    report = ("==1==ERROR: AddressSanitizer: container-overflow on address 0x00\n"
              "    #0 0x1 in read_container /test/repository/main.c:12\n"
              "SUMMARY: AddressSanitizer: container-overflow\n")
    result = c_runner.classify_run("", report, 1, target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "CONFIRMED"
    assert result["diagnostic_class"] == "asan:container-overflow"


def test_unlisted_asan_kind_still_confirms_with_target_frame():
    report = ("==1==ERROR: AddressSanitizer: some-new-check on address 0x00\n"
              "    #0 0x1 in handler /test/repository/main.c:30\n")
    result = c_runner.classify_run("", report, 1, target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "CONFIRMED"
    assert result["diagnostic_class"] == "asan:some-new-check"


def test_bare_segv_is_recorded_as_crash_not_not_reproduced():
    result = c_runner.classify_run("", "Segmentation fault\n", 139,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["status"] != "NOT_REPRODUCED"
    assert result["crash"] == {"detected": True, "signal": "SIGSEGV", "exit_code": 139}
    assert result["diagnostic_class"] == "signal:segv"
    assert result["terminal_reason"] == "crash_signal_unknown"


def test_asan_segv_without_summary_keeps_target_anchor():
    report = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x00\n"
              "    #0 0x1 in parse /test/repository/main.c:44\n")
    result = c_runner.classify_run("", report, 139, target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["status"] != "NOT_REPRODUCED"
    assert result["diagnostic_class"] == "asan:segv"
    assert result["anchor"]["kind"] == "target"
    assert result["terminal_reason"] == "crash_signal_target"


def test_sigabrt_is_recorded_as_crash():
    result = c_runner.classify_run("", "Aborted (core dumped)\n", 134,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["crash"]["signal"] == "SIGABRT"
    assert result["terminal_reason"].startswith("crash_signal_")


def test_long_stack_overflow_keeps_first_target_frame_and_summary():
    result = c_runner.classify_run("", _stack_overflow(2000), -6,
                                   target_path=TARGET, driver_path=DRIVER)
    evidence = result["evidence"][0]["content"]
    assert len(evidence) <= 6000
    assert "main.c:68" in evidence
    assert "SUMMARY: AddressSanitizer: stack-overflow" in evidence
    assert "ABORTING" in evidence
    assert "其余" in evidence


def test_driver_frame_before_target_is_not_confirmed():
    report = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x00\n"
              "    #0 0x1 in main /test/test_exploit.c:9\n"
              "    #1 0x2 in parse /test/repository/main.c:44\n")
    result = c_runner.classify_run("", report, 1, target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["anchor"]["kind"] == "driver"
    assert "测试驱动" in result["details"]
    assert result["terminal_reason"] == "driver_fault"


@pytest.mark.parametrize("code,stderr,signal_name", [
    (-11, "", "SIGSEGV"),
    (139, "Segmentation fault", "SIGSEGV"),
    (-6, "", "SIGABRT"),
    (134, "Aborted", "SIGABRT"),
    (-7, "", "SIGBUS"),
    (-4, "", "SIGILL"),
    (-8, "", "SIGFPE"),
])
def test_any_signal_never_becomes_not_reproduced(code, stderr, signal_name):
    result = c_runner.classify_run("", stderr, code, target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["crash"]["detected"] is True
    assert result["crash"]["signal"] == signal_name


def test_collected_crash_details_say_detected():
    execution = docker_executor.DockerExecutionResult()
    execution.stdout = json.dumps(c_runner.classify_run(
        "", "Segmentation fault\n", 139, target_path=TARGET, driver_path=DRIVER))
    execution.exit_code = 0
    result = collect_result({"id": "f"}, {"test_script": "x", "dockerfile": "x"}, execution)
    assert result.status == "INCONCLUSIVE"
    assert "已捕获崩溃" in result.details
    assert result.crash["signal"] == "SIGSEGV"


def test_glibc_heap_corruption_is_recorded_as_crash():
    result = c_runner.classify_run("", "free(): invalid pointer\n", -6,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["diagnostic_class"] == "libc:heap_corruption"
    assert result["crash"]["detected"] is True
    assert "内存破坏" in result["details"]


def test_glibc_corruption_with_target_frame_is_confirmed():
    stderr = ("free(): invalid pointer\n"
              "    #0 0x40131e in default_free /test/repository/main.c:85\n")
    result = c_runner.classify_run("", stderr, -6,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "CONFIRMED"
    assert result["terminal_reason"] == "libc_corruption_target"


def test_bare_abort_is_crash_but_not_confirmed():
    result = c_runner.classify_run("", "Aborted\n", -6,
                                   target_path=TARGET, driver_path=DRIVER)
    assert result["status"] == "INCONCLUSIVE"
    assert result["crash"]["detected"] is True
    assert result["diagnostic_class"] == "signal:abort"
