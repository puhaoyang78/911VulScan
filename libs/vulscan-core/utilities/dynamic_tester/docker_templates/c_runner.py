# Modified 2026-10-23 for the VulScan-only product namespace.
"""C/C++ 单文件复现执行器；生产环境仅在隔离 Docker 容器内调用。

此模块不提供宿主机扫描入口。原生测试仅执行仓库内已审阅的测试样例。
编译、执行分别计时；编译器诊断、普通崩溃、sanitizer 启动失败均不能确认漏洞。
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


STATUSES = {"CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR"}
SANITIZER_FLAGS = [
    "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all", "-fno-pie", "-no-pie",
]
# Generic DEADLYSIGNAL may be an ASan startup fault. Only concrete diagnostic
# classes count; toolchain/configuration failures never become CONFIRMED.
_ASAN = re.compile(
    r"(?:ERROR|SUMMARY): AddressSanitizer: (heap-buffer-overflow|stack-buffer-overflow|"
    r"global-buffer-overflow|dynamic-stack-buffer-overflow|heap-use-after-free|"
    r"stack-use-after-return|stack-use-after-scope|double-free|alloc-dealloc-mismatch|"
    r"new-delete-type-mismatch|attempting free on address which was not malloc\(\)-ed)\b"
)
_UBSAN = re.compile(
    r"[^\n]+:\d+:\d+: runtime error: (?:signed integer overflow|"
    r"index .* out of bounds|load of .* insufficient space|store to .* insufficient space|"
    r"load of misaligned address|store to misaligned address|"
    r"member access within misaligned address|member access within null pointer|"
    r"load of null pointer|store to null pointer|division by zero|"
    r"shift exponent|left shift of|shift base|pointer index expression|"
    r"applying non-zero offset|execution reached an unreachable program point)"
)
_CONFIG_ERRORS = (
    "ASan runtime does not come first", "Shadow memory range interleaves",
    "ReserveShadowMemoryRange failed", "AddressSanitizer failed to allocate",
    "LeakSanitizer has encountered a fatal error", "failed to mmap",
    "error while loading shared libraries",
)


def _result(status: str, details: str, *outputs: str) -> dict:
    def bounded_output(text):
        # This runner is copied into Docker as a standalone file. Preserve
        # compiler errors at the end of long logs before the collector applies
        # its own prompt/report budget. Verdict evidence retains its old bound.
        if status == "ERROR" and len(text) > 12000:
            return text[:5900] + "\n[... diagnostic truncated ...]\n" + text[-5900:]
        return text[:12000]

    return {"status": status, "details": details, "evidence": [
        {"type": "command_output", "content": bounded_output(text)}
        for text in outputs if text
    ]}


def parse_result(stdout: str) -> dict | None:
    """读取严格类型的结果对象；日志行可以出现在最终 JSON 之前。"""
    candidates = [stdout.strip(), *reversed(stdout.splitlines())]
    for value in candidates:
        try:
            obj = json.loads(value)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        if (not isinstance(obj.get("status"), str) or obj["status"] not in STATUSES
                or not isinstance(obj.get("details"), str)
                or not isinstance(obj.get("evidence", []), list)):
            continue
        if any(not isinstance(e, dict) or not isinstance(e.get("type"), str)
               or not isinstance(e.get("content"), str)
               for e in obj.get("evidence", [])):
            continue
        return obj
    return None


def _diagnostic_matches_target(stderr: str, target_path: str | None,
                               driver_path: str | None) -> bool:
    """首个属于目标或驱动的源码位置必须指向真实目标，防止把驱动缺陷算给目标。"""
    if not target_path:
        return False
    target = re.compile(re.escape(target_path) + r":\d+(?::\d+)?")
    driver = re.compile(re.escape(driver_path) + r":\d+(?::\d+)?") if driver_path else None
    for line in stderr.splitlines():
        if target.search(line):
            return True
        if driver and driver.search(line):
            return False
    return False


def classify_run(stdout: str, stderr: str, returncode: int, *,
                 target_path: str | None = None, driver_path: str | None = None) -> dict:
    """先检查运行环境，再判定 sanitizer 证据，最后读取测试自身结果。"""
    if any(marker in stderr for marker in _CONFIG_ERRORS):
        return _result("ERROR", "C/C++ sanitizer 或运行环境初始化失败，未完成验证。", stderr)
    asan = _ASAN.search(stderr)
    ubsan = _UBSAN.search(stderr)
    if asan or ubsan:
        if returncode == 0:
            return _result("INCONCLUSIVE", "检测到 sanitizer 形式的诊断文本，但程序正常退出；缺少错误终止信号，不能确认漏洞。", stderr, stdout)
        if not _diagnostic_matches_target(stderr, target_path, driver_path):
            return _result("INCONCLUSIVE", "sanitizer 检测到缺陷，但诊断未指向真实目标源文件，或首先指向测试驱动，不能确认原始发现。", stderr)
        kind = asan.group(1) if asan else "UndefinedBehaviorSanitizer"
        return _result("CONFIRMED", f"C/C++ 测试触发 {kind} 运行时诊断；请结合调用栈核对原始发现。", stderr)
    if returncode != 0:
        return _result("INCONCLUSIVE", f"C/C++ 测试异常退出（退出码 {returncode}），缺少具体 sanitizer 诊断，无法确认漏洞。", stderr, stdout)
    parsed = parse_result(stdout)
    if parsed is not None:
        if parsed["status"] == "CONFIRMED":
            # The generated driver is untrusted: its own assertion (even with
            # nonempty evidence) cannot establish that it executed the target.
            # This template only auto-confirms target-anchored sanitizer faults.
            return {**parsed, "status": "INCONCLUSIVE",
                    "details": "测试自行声称已确认，但缺少指向真实目标的 sanitizer 诊断与错误终止，当前 C/C++ 模板不能自动确认。原测试说明：" + parsed["details"]}
        return parsed
    return _result("INCONCLUSIVE", "C/C++ 测试正常退出，但未输出有效的结构化验证结果；不能据此判断已修复。", stderr, stdout)


def compile_command(source: Path, binary: Path, language: str) -> list[str]:
    if language not in {"c", "cpp"}:
        raise ValueError("不支持的 C/C++ 编译语言")
    # C's standard math functions need explicit libm linkage on this Linux
    # toolchain. Keep the library after the source for --as-needed linkers.
    return ["g++" if language == "cpp" else "gcc",
            "-std=c++17" if language == "cpp" else "-std=c11",
            *SANITIZER_FLAGS, "-x", "c++" if language == "cpp" else "c",
            str(source), "-o", str(binary), "-lm"]


def _timeout_output(value: str | bytes | None) -> str:
    # TimeoutExpired may contain bytes even when subprocess.run(text=True).
    # A timeout can also interrupt a UTF-8 code point; retain the diagnostics
    # without letting decoding errors hide the original failure.
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_test(source: Path, language: str, *, timeout: int = 30,
             compile_timeout: int = 60, target_filename: str | None = None) -> dict:
    """编译并执行一个复现单元。生产调用方必须已处于 Docker 沙箱内。"""
    source = Path(source).resolve()
    if not source.is_file():
        return _result("ERROR", "C/C++ 测试源文件不存在。")
    if language not in {"c", "cpp"}:
        return _result("ERROR", "不支持的 C/C++ 编译语言。")
    target_path = None
    if target_filename is not None:
        if (not isinstance(target_filename, str) or not target_filename
                or Path(target_filename).is_absolute() or ".." in Path(target_filename).parts):
            return _result("ERROR", "C/C++ 目标源文件名配置无效。")
        target = source.parent / target_filename
        if not target.resolve().is_relative_to(source.parent):
            return _result("ERROR", "C/C++ 目标源文件超出测试目录。")
        if not target.is_file() or target.resolve() == source:
            return _result("ERROR", "C/C++ 真实目标源文件缺失，或与测试驱动重复。")
        target_path = str(target.resolve())
    with tempfile.TemporaryDirectory(prefix="vulscan-c-", dir="/tmp") as scratch:
        binary = Path(scratch) / "test_exploit"
        command = compile_command(source, binary, language)
        try:
            built = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=compile_timeout, cwd=source.parent)
        except subprocess.TimeoutExpired as exc:
            return _result("ERROR", "C/C++ 编译超时，未执行测试。",
                           _timeout_output(exc.stderr), _timeout_output(exc.stdout))
        except OSError as exc:
            return _result("ERROR", f"C/C++ 编译器无法启动：{exc}")
        if built.returncode:
            result = _result("ERROR", "C/C++ 编译失败，未执行测试；请检查源文件、依赖和语言标准。",
                             built.stderr, built.stdout)
            if (target_path and re.search(re.escape(target_path) + r":\d+:\d+: fatal error: .+: No such file or directory", built.stderr)
                    or "cannot find -l" in built.stderr):
                result["retryable"] = False
                result["details"] += " 目标构建依赖缺失，改写测试无法补齐，停止模型重试。"
            return result
        env = dict(os.environ)
        # Never inherit overrides disabling detection, leaking reports to a file,
        # or adding a preload. The production container has no host env/secrets.
        env.pop("LD_PRELOAD", None)
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        try:
            executed = subprocess.run([str(binary)], capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", cwd=scratch,
                                      env=env, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            return _result("INCONCLUSIVE", "C/C++ 测试执行超时，无法确定漏洞是否复现。",
                           _timeout_output(exc.stderr), _timeout_output(exc.stdout))
        except OSError as exc:
            return {**_result("ERROR", f"C/C++ 测试程序无法启动：{exc}"), "retryable": False}
        return classify_run(executed.stdout, executed.stderr, executed.returncode,
                            target_path=target_path, driver_path=str(source))


def main() -> None:
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            spec = json.load(handle)
        filename = spec["test_filename"]
        if (not isinstance(filename, str) or Path(filename).name != filename
                or filename in {"", ".", ".."}):
            raise ValueError("测试文件名必须是当前目录中的普通文件名")
        result = run_test(Path(filename), spec["language"], target_filename=spec["target_filename"])
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        result = _result("ERROR", f"C/C++ 测试配置无效：{exc}")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
