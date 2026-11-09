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
    r"global-buffer-overflow|dynamic-stack-buffer-overflow|container-overflow|"
    r"heap-use-after-free|stack-use-after-return|stack-use-after-scope|double-free|"
    r"invalid-free|alloc-dealloc-mismatch|new-delete-type-mismatch|"
    r"negative-size-param|memcpy-param-overlap|stack-overflow|odr-violation|"
    r"attempting free on address which was not malloc\(\)-ed)\b"
)
# 未列入上面的 ASan 类别（例如新编译器新增的检查）仍然要能识别。
# SEGV/BUS 走单独的信号分支，避免把没有读写类型和调用栈的启动期崩溃算成漏洞。
_ASAN_ANY = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer: ([a-zA-Z][a-zA-Z0-9-]*)\b")
# A bare DEADLYSIGNAL also occurs during ASan startup. A signal report must
# contain the access type, a symbolized stack and its closing summary.
_ASAN_SIGNAL = re.compile(
    r"ERROR: AddressSanitizer: (SEGV|BUS)\b.*?"
    r"SUMMARY: AddressSanitizer: \1\b[^\n]*", re.S,
)
_SIGNAL_NAMES = {
    4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV",
}
_SIGNAL_TEXT = {
    "SIGSEGV": ("Segmentation fault", "Segmentation fault (core dumped)"),
    "SIGABRT": ("Aborted", "Aborted (core dumped)"),
    "SIGBUS": ("Bus error", "Bus error (core dumped)"),
    "SIGILL": ("Illegal instruction", "Illegal instruction (core dumped)"),
    "SIGFPE": ("Floating point exception", "Floating point exception (core dumped)"),
}
_FRAME = re.compile(r"^\s*#\d+\s+")
_UBSAN = re.compile(
    r"[^\n]+:\d+:\d+: runtime error: (?:signed integer overflow|"
    r"index .* out of bounds|load of .* insufficient space|store to .* insufficient space|"
    r"load of misaligned address|store to misaligned address|"
    r"member access within misaligned address|member access within null pointer|"
    r"load of null pointer|store to null pointer|division by zero|"
    r"shift exponent|left shift of|shift base|pointer index expression|"
    r"applying non-zero offset|execution reached an unreachable program point)"
)
# glibc 自己发现堆/栈被写坏时会 abort。这类消息说明确实发生了内存破坏，
# 但没有源码位置，不能直接算到目标函数头上。
_LIBC_CORRUPTION = re.compile(
    r"(free\(\): invalid pointer|free\(\): invalid next size|"
    r"malloc\(\): corrupted top size|malloc\(\): invalid size|"
    r"double free or corruption|corrupted size vs\. prev_size|"
    r"munmap_chunk\(\): invalid pointer|realloc\(\): invalid next size|"
    r"\*\*\* stack smashing detected \*\*\*|"
    r"\*\*\* buffer overflow detected \*\*\*)"
)
_CONFIG_ERRORS = (
    "ASan runtime does not come first", "Shadow memory range interleaves",
    "ReserveShadowMemoryRange failed", "AddressSanitizer failed to allocate",
    "LeakSanitizer has encountered a fatal error", "failed to mmap",
    "error while loading shared libraries",
)


def _keep_key_lines(text: str, limit: int = 6000) -> str:
    """长日志只留关键行：错误行、结论行和开头几条调用栈。

    栈溢出可以有几千行，直接截断会把目标函数所在的第一帧和结尾的
    SUMMARY/ABORTING 一起丢掉，人看到的就只剩"退出码 -6"。
    """
    if len(text) <= limit:
        return text
    head = text[:1200]
    tail = text[-1200:]
    picked = []
    frames = 0
    omitted = 0
    for line in text.splitlines():
        if _FRAME.match(line):
            if frames < 8:
                picked.append(line)
            else:
                omitted += 1
            frames += 1
            continue
        if re.search(r"ERROR:|SUMMARY:|ABORTING|runtime error|"
                     r"Segmentation fault|Aborted|Bus error|Illegal instruction|"
                     r"Floating point exception|AddressSanitizer:|DEADLYSIGNAL", line):
            picked.append(line)
    middle = "\n".join(picked)
    if omitted:
        middle += f"\n[... 其余 {omitted} 层调用栈已省略 ...]"
    combined = head + "\n[... 中间内容已省略 ...]\n" + middle + "\n[... 结尾 ...]\n" + tail
    return combined[:limit]


def _result(status: str, details: str, *outputs: str,
            failure_phase: str = "", retryable: bool | None = None,
            diagnostic_class: str = "", crash: dict | None = None,
            anchor: dict | None = None, terminal_reason: str = "") -> dict:
    def bounded_output(text):
        # This runner is copied into Docker as a standalone file. Preserve
        # compiler errors at the end of long logs before the collector applies
        # its own prompt/report budget.
        if status == "ERROR" and len(text) > 12000:
            return text[:5900] + "\n[... diagnostic truncated ...]\n" + text[-5900:]
        if status == "ERROR":
            return text[:12000]
        return _keep_key_lines(text)

    result = {"status": status, "details": details, "evidence": [
        {"type": "command_output", "content": bounded_output(text)}
        for text in outputs if text
    ]}
    if failure_phase:
        result["failure_phase"] = failure_phase
    if retryable is not None:
        result["retryable"] = retryable
    if diagnostic_class:
        result["diagnostic_class"] = diagnostic_class
    if crash:
        result["crash"] = crash
    if anchor:
        result["anchor"] = anchor
    if terminal_reason:
        result["terminal_reason"] = terminal_reason
    return result


def _find_anchor(text: str, target_path: str | None, driver_path: str | None) -> dict:
    """从调用栈里找第一个属于目标或测试驱动的源码位置。"""
    if target_path:
        target = re.compile(re.escape(target_path) + r":(\d+)")
    else:
        target = None
    driver = re.compile(re.escape(driver_path) + r":(\d+)") if driver_path else None
    for line in text.splitlines():
        # UBSan 的源码位置就在诊断行本身（没有 #N 栈帧），所以这里不强制要求帧格式。
        if target:
            found = target.search(line)
            if found:
                return {"kind": "target", "file": target_path, "line": int(found.group(1))}
        if driver:
            found = driver.search(line)
            if found:
                return {"kind": "driver", "file": driver_path, "line": int(found.group(1))}
    return {"kind": "unknown"}


def _signal_name(returncode: int) -> str:
    if returncode < 0:
        number = -returncode
    elif returncode >= 128:
        number = returncode - 128
    else:
        return ""
    return _SIGNAL_NAMES.get(number, f"signal-{number}")


def _crash_payload(returncode: int, stderr: str) -> dict:
    name = _signal_name(returncode)
    text_hit = ""
    for candidate, markers in _SIGNAL_TEXT.items():
        if any(marker in stderr for marker in markers):
            text_hit = candidate
            break
    if not name and text_hit:
        name = text_hit
    if not name:
        return {}
    access = ""
    if re.search(r"The signal is caused by a (READ|WRITE) memory access", stderr):
        access = re.search(r"The signal is caused by a (READ|WRITE) memory access", stderr).group(1)
    return {"detected": True, "signal": name, "exit_code": returncode,
            **({"access": access} if access else {})}


def _diagnostic_matches_target(stderr: str, target_path: str | None,
                               driver_path: str | None) -> bool:
    return _find_anchor(stderr, target_path, driver_path)["kind"] == "target"


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
        return _result("ERROR", "C/C++ sanitizer 或运行环境初始化失败，未完成验证。", stderr,
                       failure_phase="environment", retryable=False,
                       diagnostic_class="config", terminal_reason="environment_config")
    asan = _ASAN.search(stderr)
    ubsan = _UBSAN.search(stderr)
    signal = _ASAN_SIGNAL.search(stderr)
    if signal and not (re.search(r"The signal is caused by a (?:READ|WRITE) memory access", signal[0])
                       and re.search(r"(?m)^\s*#\d+\s+", signal[0])):
        signal = None
    # 未列入清单的 ASan 类别（新编译器、新检查）也要识别；SEGV/BUS 留给下面的信号分支。
    generic = None
    if not (asan or signal):
        match = _ASAN_ANY.search(stderr)
        if match and match.group(1) not in {"SEGV", "BUS", "DEADLYSIGNAL"}:
            generic = match
    diagnostic = asan or ubsan or signal or generic
    if diagnostic:
        if returncode == 0:
            return _result("INCONCLUSIVE", "检测到 sanitizer 形式的诊断文本，但程序正常退出；缺少错误终止信号，不能确认漏洞。", stderr, stdout,
                           diagnostic_class="sanitizer", terminal_reason="normal_exit_with_diagnostic")
        # Ignore source paths printed before the actual sanitizer report.
        trace = signal[0] if diagnostic is signal else stderr[diagnostic.start():]
        anchor = _find_anchor(trace, target_path, driver_path)
        if anchor["kind"] != "target":
            details = ("sanitizer 检测到崩溃，但调用栈未关联原始目标文件；需修正测试以覆盖原始发现。"
                       if anchor["kind"] == "unknown" else
                       "sanitizer 检测到崩溃，但第一个源码位置属于测试驱动；需修正测试以覆盖原始发现。")
            return _result("INCONCLUSIVE", details, stderr,
                           failure_phase="analysis", retryable=anchor["kind"] == "unknown",
                           diagnostic_class="sanitizer", anchor=anchor,
                           terminal_reason="no_target_anchor" if anchor["kind"] == "unknown" else "driver_fault")
        if asan:
            kind = asan.group(1)
        elif signal:
            kind = "AddressSanitizer " + signal.group(1)
        elif generic:
            kind = generic.group(1)
        else:
            kind = "UndefinedBehaviorSanitizer"
        short = kind.replace("AddressSanitizer ", "").replace(
            "attempting free on address which was not malloc()-ed", "invalid-free")
        return _result("CONFIRMED", f"C/C++ 测试触发 {kind} 运行时诊断；请结合调用栈核对原始发现。", stderr,
                       diagnostic_class=("ubsan" if ubsan else "asan:" + short.lower()),
                       anchor=anchor, terminal_reason="sanitizer_fault")
    if returncode != 0:
        crash = _crash_payload(returncode, stderr)
        anchor = _find_anchor(stderr, target_path, driver_path)
        libc = _LIBC_CORRUPTION.search(stderr)
        if libc:
            hit = libc.group(1)
            target_hit = anchor["kind"] == "target"
            return _result(
                "CONFIRMED" if target_hit else "INCONCLUSIVE",
                (f"glibc 检测到内存破坏（{hit}），且调用栈指向目标文件。"
                 if target_hit else
                 f"glibc 检测到内存破坏（{hit}），但没有源码位置；"
                 "已记录为崩溃，需人工确认是目标还是测试驱动造成的。"),
                stderr, stdout,
                failure_phase="analysis", retryable=False,
                diagnostic_class="libc:heap_corruption",
                crash=crash or {"detected": True,
                                "signal": _signal_name(returncode) or "SIGABRT",
                                "exit_code": returncode},
                anchor=anchor,
                terminal_reason=("libc_corruption_target" if target_hit
                                 else "libc_corruption_unanchored"),
            )
        asan_signal = re.search(r"(?:ERROR|SUMMARY): AddressSanitizer: (SEGV|BUS)\b", stderr)
        if asan_signal:
            name = "SIG" + asan_signal.group(1)
            return _result("INCONCLUSIVE", f"C/C++ 测试触发 ASan 内存访问崩溃（{name}，退出码 {returncode}），但读写类型或调用栈不完整，无法直接确认。", stderr, stdout,
                           failure_phase="analysis", retryable=False,
                           diagnostic_class="asan:" + asan_signal.group(1).lower(),
                           crash=crash or {"detected": True, "signal": name, "exit_code": returncode},
                           anchor=anchor,
                           terminal_reason="crash_signal_target" if anchor["kind"] == "target" else "crash_signal_unknown")
        if crash:
            signal_key = crash["signal"].lower().replace("sig", "")
            if signal_key == "abrt":
                signal_key = "abort"
            return _result("INCONCLUSIVE", f"C/C++ 测试进程因 {crash['signal']} 崩溃（退出码 {returncode}），但没有 sanitizer 诊断；已记录崩溃，不能当作未复现。", stderr, stdout,
                           failure_phase="run", retryable=False,
                           diagnostic_class="signal:" + signal_key,
                           crash=crash, anchor=anchor,
                           terminal_reason="crash_signal_target" if anchor["kind"] == "target" else "crash_signal_unknown")
        return _result("INCONCLUSIVE", f"C/C++ 测试异常退出（退出码 {returncode}），没有可识别的崩溃信号或 sanitizer 诊断，无法确认漏洞。", stderr, stdout,
                       failure_phase="run", diagnostic_class="none",
                       terminal_reason="unknown_nonzero_exit")
    parsed = parse_result(stdout)
    if parsed is not None:
        if parsed["status"] == "CONFIRMED":
            # The generated driver is untrusted: its own assertion (even with
            # nonempty evidence) cannot establish that it executed the target.
            # This template only auto-confirms target-anchored sanitizer faults.
            return {**parsed, "status": "INCONCLUSIVE",
                    "details": "测试自行声称已确认，但缺少指向真实目标的 sanitizer 诊断与错误终止，当前 C/C++ 模板不能自动确认。原测试说明：" + parsed["details"]}
        return parsed
    return _result("INCONCLUSIVE", "C/C++ 测试正常退出，但未输出有效的结构化验证结果；不能据此判断已修复。", stderr, stdout,
                   terminal_reason="coverage_miss")


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
                           _timeout_output(exc.stderr), _timeout_output(exc.stdout),
                           failure_phase="build", retryable=False)
        except OSError as exc:
            return _result("ERROR", f"C/C++ 编译器无法启动：{exc}",
                           failure_phase="environment", retryable=False)
        if built.returncode:
            result = _result("ERROR", "C/C++ 编译失败，未执行测试；请检查源文件、依赖和语言标准。",
                             built.stderr, built.stdout, failure_phase="build")
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
                           _timeout_output(exc.stderr), _timeout_output(exc.stdout),
                           failure_phase="run", retryable=False)
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
