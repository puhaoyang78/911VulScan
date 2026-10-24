# Modified 2026-10-23 for the VulScan-only product namespace.
"""真实 GCC/G++ fixture 验证 + 无 Docker 环境中的执行接线回归。

仅编译本测试所创建的源码和仓库内已审阅样例；不扫描外部目标、不调用模型。
Docker 路由测试使用 mock，不能替代真正的容器集成验证。
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from utilities.dynamic_tester import should_skip_for_language
from utilities.dynamic_tester import docker_executor as docker
from utilities.dynamic_tester.docker_templates import c_runner
from utilities.dynamic_tester.result_collector import collect_result, _parse_container_output
from utilities.dynamic_tester import test_generator as generator


FIXTURES = Path(__file__).parent / "fixtures" / "dynamic_c"


@pytest.mark.parametrize("filename,alias,expected", [
    ("src/unit.c", "cpp", "c"), ("src/unit.cpp", "python", "cpp"),
    ("src/unit.C", "c", "cpp"), ("src/unit.cc", None, "cpp"),
    ("src/unit.cxx", "c", "cpp"), ("src/unit.hpp", "c", "cpp"),
    ("src/unit.hh", None, "cpp"), ("src/unit.hxx", None, "cpp"),
    ("src/unit.h", "c++", "cpp"), ("src/unit.h", "c", "c"),
    ("unknown", " C++ ", "cpp"), ("unknown", "cpp", "cpp"),
    ("unknown", "C/C++", "cpp"), ("unknown", "cxx", "cpp"),
    ("unknown", "C", "c"),
])
def test_language_resolution(filename, alias, expected):
    assert generator.resolve_native_language(filename, alias) == expected
    assert generator.resolve_docker_template(filename, alias) == "c"
    assert should_skip_for_language(filename, alias) == (False, "")


def test_no_native_fallback_for_another_language():
    assert generator.resolve_native_language("main.py", "cpp") is None
    assert generator.resolve_docker_template("main.zig", "cpp") is None
    assert should_skip_for_language("main.zig", "cpp")[0]


@pytest.mark.parametrize("language,compiler,standard", [("c", "gcc", "-std=c11"), ("cpp", "g++", "-std=c++17")])
def test_compile_command(language, compiler, standard):
    command = c_runner.compile_command(Path("with spaces.c"), Path("/tmp/bin"), language)
    assert command[0] == compiler
    assert standard in command
    assert "-fsanitize=address,undefined" in command
    assert "-fno-sanitize-recover=all" in command
    # libm follows the source so GNU ld's --as-needed does not discard it.
    assert command[-4:] == ["with spaces.c", "-o", "/tmp/bin", "-lm"]


@pytest.mark.parametrize("language,suffix", [("c", ".c"), ("cpp", ".cpp")])
@pytest.mark.parametrize("variant,expected", [("vulnerable", "CONFIRMED"), ("fixed", "NOT_REPRODUCED")])
def test_real_sanitized_native_fixtures(tmp_path, language, suffix, variant, expected):
    compiler = "gcc" if language == "c" else "g++"
    if not shutil.which(compiler):
        pytest.skip(f"缺少 {compiler}，未运行真实编译验证")
    shutil.copy2(FIXTURES / f"{variant}{suffix}", tmp_path / f"target{suffix}")
    # The driver calls exactly the same index in vulnerable and fixed target code.
    test = tmp_path / f"test_exploit{suffix}"
    test.write_text('#include <stdio.h>\n#include "target' + suffix + '"\n'
                    'int main(void) { volatile int index = 8;\n'
                    'int result = inspect_index(index);\n'
                    'if (result != -1) return 2;\n'
                    'puts("{\\"status\\":\\"NOT_REPRODUCED\\",\\"details\\":\\"越界输入被拒绝\\",\\"evidence\\":[]}");\n'
                    'return 0; }\n', encoding="utf-8")
    result = c_runner.run_test(test, language, target_filename=f"target{suffix}")
    assert result["status"] == expected, result
    if variant == "vulnerable":
        assert ("heap-buffer-overflow" in result["evidence"][0]["content"]
                or "insufficient space" in result["evidence"][0]["content"])
        assert f"target{suffix}" in result["evidence"][0]["content"]
    else:
        assert result["details"] == "越界输入被拒绝"


def test_real_compile_failure_is_error(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("缺少 GCC，未运行真实编译验证")
    source = tmp_path / "broken.c"
    source.write_text("#include <missing_project_header.h>\nint main(void) { return 0; }\n")
    result = c_runner.run_test(source, "c")
    assert result["status"] == "ERROR"
    assert "编译失败" in result["details"]
    assert "missing_project_header.h" in result["evidence"][0]["content"]


def test_real_ubsan_fixture(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("缺少 GCC，未运行真实编译验证")
    source = tmp_path / "overflow.c"
    (tmp_path / "target.c").write_text("#include <limits.h>\nint overflow(void) { volatile int x = INT_MAX; return x + 1; }\n")
    source.write_text('#include "target.c"\nint main(void) { return overflow(); }\n')
    result = c_runner.run_test(source, "c", target_filename="target.c")
    assert result["status"] == "CONFIRMED", result
    assert "signed integer overflow" in result["evidence"][0]["content"]


@pytest.mark.parametrize("stderr,code,status", [
    ("AddressSanitizer:DEADLYSIGNAL", -11, "INCONCLUSIVE"),
    ("Segmentation fault", 139, "INCONCLUSIVE"),
    ("ASan runtime does not come first in initial library list", 1, "ERROR"),
    ("Shadow memory range interleaves with an existing memory mapping", 1, "ERROR"),
    ("error while loading shared libraries", 127, "ERROR"),
    ("/test/target.c:2:3: runtime error: signed integer overflow: 2 + 3", 1, "CONFIRMED"),
    ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x00\n#0 target /test/target.c:2:3", 1, "CONFIRMED"),
    ("ERROR: AddressSanitizer: failed to mmap 0x123", 1, "ERROR"),
    ("compiler: unknown sanitizer option", 1, "INCONCLUSIVE"),
])
def test_diagnostic_classification(stderr, code, status):
    assert c_runner.classify_run("", stderr, code, target_path="/test/target.c", driver_path="/test/test_exploit.c")["status"] == status


def test_clean_exit_without_verdict_is_not_proof():
    assert c_runner.classify_run("", "", 0)["status"] == "INCONCLUSIVE"
    claimed = json.dumps({"status": "NOT_REPRODUCED", "details": "未复现", "evidence": []})
    assert c_runner.classify_run(claimed, "", 2)["status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("payload", ["null", "[]", "true", "42", '{"status": []}',
    '{"status":"CONFIRMED","evidence":"invalid"}', '{"status":"CONFIRMED","details":{}}'])
def test_malformed_json_cannot_crash_collector(payload):
    assert _parse_container_output(payload) is None
    assert c_runner.parse_result(payload) is None
    execution = docker.DockerExecutionResult()
    execution.stdout, execution.exit_code = payload, 0
    result = collect_result({"id": "test"}, {"test_script": "x", "dockerfile": "x"}, execution)
    assert result.status == "ERROR"


def test_nonzero_container_cannot_claim_confirmation():
    execution = docker.DockerExecutionResult()
    execution.stdout = '{"status":"CONFIRMED","details":"伪结果","evidence":[]}'
    execution.exit_code = 127
    assert collect_result({"id": "a"}, {}, execution).status == "ERROR"


@pytest.mark.parametrize("exception,expected", [
    (FileNotFoundError("gcc"), "ERROR"),
    (subprocess.TimeoutExpired(["gcc"], 60), "ERROR"),
])
def test_compiler_startup_failures(tmp_path, monkeypatch, exception, expected):
    source = tmp_path / "test.c"
    source.write_text("int main(void){return 0;}")
    def failing_run(*args, **kwargs):
        raise exception
    monkeypatch.setattr(c_runner.subprocess, "run", failing_run)
    assert c_runner.run_test(source, "c")["status"] == expected


def test_runtime_timeout(tmp_path, monkeypatch):
    source = tmp_path / "test.c"
    source.write_text("int main(void){return 0;}")
    def fake_run(command, **kwargs):
        if command[0] == "gcc":
            return subprocess.CompletedProcess(command, 0, "", "")
        raise subprocess.TimeoutExpired(command, 30)
    monkeypatch.setattr(c_runner.subprocess, "run", fake_run)
    assert c_runner.run_test(source, "c")["status"] == "INCONCLUSIVE"


def test_generator_uses_fixed_native_template(monkeypatch):
    payload = {"dockerfile": "FROM attacker-image", "test_script": "int main(void){return 0;}",
               "test_filename": "wrong.py", "requirements": None, "docker_compose": None}
    seen = []
    def fake_completion(*args, **kwargs):
        seen.append((args, kwargs))
        return json.dumps(payload)
    monkeypatch.setattr(generator, "simple_text", fake_completion)
    finding = {"location": {"file": "target.cpp"}}
    generated = generator.generate_test(finding, {"language": "c"}, None)
    assert generated["native_language"] == "cpp"
    assert generated["test_filename"] == "test_exploit.cpp"
    assert generated["dockerfile"] == generator._native_dockerfile()
    assert "真实目标函数" in seen[0][0][1]
    assert "简体中文" in seen[0][1]["system"]
    retried = generator.regenerate_test(finding, {"language": "c"}, generated, "编译失败", None)
    assert retried["native_language"] == "cpp"


def test_native_dependency_limit_is_honest(monkeypatch):
    payload = {"dockerfile": "x", "test_script": "x", "test_filename": "test.c", "requirements": "opencv"}
    monkeypatch.setattr(generator, "simple_text", lambda *a, **k: json.dumps(payload))
    assert generator.generate_test({"location": {"file": "t.c"}}, {}, None) is None


def test_mocked_docker_native_staging_and_isolation(tmp_path, monkeypatch):
    source = tmp_path / "target.cpp"
    source.write_text("int target() { return 1; }")
    generated = {"native_language": "cpp", "dockerfile": "FROM unsafe", "test_filename": "../../escape.py",
                 "test_script": '#include "target.cpp"\nint main(){return target();}'}
    seen = []
    def mock_command(command, timeout, cwd=None):
        seen.append(command)
        if command[:2] == ["docker", "info"]:
            return "fixture-daemon", "", 0, False
        if command[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "0B"}), "", 0, False
        if command[:3] == ["docker", "image", "inspect"]:
            # 共享工具链已存在：本用例只检查单条发现的构建上下文。
            return "sha256:fixture-toolchain", "", 0, False
        if command[:2] == ["docker", "build"]:
            context = Path(cwd)
            assert (context / "Dockerfile").read_text() == generator._native_dockerfile()
            assert (context / "target.cpp").read_text() == source.read_text()
            assert json.loads((context / "_vulscan_c_spec.json").read_text()) == {
                "language": "cpp", "test_filename": "test_exploit.cpp", "target_filename": "target.cpp"}
            assert (context / "_vulscan_c_runner.py").is_file()
            assert (context / "test_exploit.cpp").read_text() == generated["test_script"]
            return "", "", 0, False
        return ('{"status":"NOT_REPRODUCED","details":"未复现","evidence":[]}'
                if command[:2] == ["docker", "run"] else ""), "", 0, False
    monkeypatch.setattr(docker, "_run_command", mock_command)
    result = docker.run_single_container(generated, "test", source_file=str(source))
    assert result.success
    command = next(cmd for cmd in seen if cmd[:2] == ["docker", "run"])
    for arg in ("--read-only", "--cap-drop", "--security-opt", "--pids-limit"):
        assert arg in command
    assert command[command.index("--network") + 1] == "none"
    assert "--privileged" not in command and "-v" not in command and "--mount" not in command
    assert all(cmd[0] == "docker" for cmd in seen)  # no host compiler or target execution


def test_missing_docker_is_recorded_not_raised(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(docker.subprocess, "Popen", missing)
    execution = docker.run_single_container({"dockerfile": "FROM scratch", "test_script": "x"}, "test")
    assert execution.infrastructure_error
    assert collect_result({"id": "test"}, {}, execution).status == "ERROR"


def test_native_staging_collision_is_visible(tmp_path, monkeypatch):
    source = tmp_path / "test_exploit.c"
    source.write_text("int main(void){return 0;}")
    monkeypatch.setattr(docker, "_run_command", lambda *a, **kw: ("", "", 0, False))
    execution = docker.run_single_container({"native_language": "c", "test_script": "x"}, "test", source_file=str(source))
    assert "冲突" in execution.execution_error
    assert collect_result({"id": "test"}, {}, execution).status == "ERROR"


@pytest.mark.parametrize("evidence", [[], [{"type": "command_output", "content": "  "}],
                                       [{"type": "", "content": "x"}], [{"type": "command_output", "content": None}]])
def test_bare_confirmation_needs_meaningful_evidence(evidence):
    payload = json.dumps({"status": "CONFIRMED", "details": "声称确认", "evidence": evidence})
    assert c_runner.classify_run(payload, "", 0)["status"] == "INCONCLUSIVE"
    execution = docker.DockerExecutionResult()
    execution.stdout, execution.exit_code = payload, 0
    result = collect_result({"id": "f", "identity_key": "real-target"}, {}, execution)
    assert result.status == "INCONCLUSIVE"
    assert result.identity_key == "real-target"


def test_driver_fault_does_not_confirm_target(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("缺少 GCC，未运行真实编译验证")
    (tmp_path / "target.c").write_text("int target(void){return 0;}\n")
    source = tmp_path / "driver.c"
    source.write_text('#include "target.c"\n#include <limits.h>\n'
                      'int main(void){ volatile int x = INT_MAX; return target() + x + 1; }\n')
    result = c_runner.run_test(source, "c", target_filename="target.c")
    assert result["status"] == "INCONCLUSIVE", result
    assert "测试驱动" in result["details"]


def test_sanitizer_without_target_source_is_inconclusive():
    diagnostic = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 /test/driver.c:2:3"
    assert c_runner.classify_run("", diagnostic, 1)["status"] == "INCONCLUSIVE"
    assert c_runner.classify_run("", diagnostic, 1, target_path="/test/target.c")["status"] == "INCONCLUSIVE"
    diagnostic += "\n#1 /test/target.c:9:2"
    assert c_runner.classify_run("", diagnostic, 1, target_path="/test/target.c",
                                 driver_path="/test/driver.c")["status"] == "INCONCLUSIVE"


def test_native_requires_actual_source(monkeypatch):
    monkeypatch.setattr(docker, "_run_command", lambda *a, **kw: ("", "", 0, False))
    execution = docker.run_single_container({"native_language": "c", "test_script": "x"}, "test")
    assert "真实目标源文件" in execution.execution_error
    assert collect_result({"id": "test"}, {}, execution).status == "ERROR"


def test_wrapper_returns_actual_report_filename(tmp_path, monkeypatch):
    import core.dynamic_tester as wrapper
    import utilities.dynamic_tester as dynamic
    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({"findings": [{"stage2_verdict": "agreed"}]}))
    output = tmp_path / "out"
    expected = output / "DYNAMIC_TEST_RESULTS.md"
    def fake_tests(*args, **kwargs):
        expected.write_text("# 动态测试结果\n")
        return []
    monkeypatch.setattr(wrapper.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dynamic, "run_dynamic_tests", fake_tests)
    result = wrapper.run_tests(str(pipeline), str(output))
    assert result.results_md_path == str(expected)


@pytest.mark.parametrize("variant,expected", [("vulnerable", "CONFIRMED"), ("fixed", "NOT_REPRODUCED")])
def test_staged_runner_command_with_real_fixture(tmp_path, variant, expected):
    """实际执行 Docker CMD 所指的包装器；这里只用已审阅 fixture，不运行 Docker。"""
    if not shutil.which("g++"):
        pytest.skip("缺少 G++，未运行真实编译验证")
    target = FIXTURES / f"{variant}.cpp"
    generation = {
        "native_language": "cpp",
        "test_script": '#include <stdio.h>\n#include "' + target.name + '"\n'
                       'int main(void){ volatile int index=8; int result=inspect_index(index);\n'
                       'if(result != -1) return 2;\n'
                       'puts("{\\"status\\":\\"NOT_REPRODUCED\\",\\"details\\":\\"越界输入被拒绝\\",\\"evidence\\":[]}");\n'
                       'return 0;}\n',
    }
    docker._write_test_files(str(tmp_path), generation, source_file=str(target))
    completed = subprocess.run([sys.executable, "_vulscan_c_runner.py", "_vulscan_c_spec.json"],
                               cwd=tmp_path, capture_output=True, text=True, timeout=90)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)  # exactly one JSON object, no compiler stdout leakage
    assert result["status"] == expected, result
    assert completed.stderr == ""


def test_native_self_reported_confirmation_retains_evidence_but_is_inconclusive():
    evidence = [{"type": "command_output", "content": "生成程序声称已调用目标"}]
    payload = json.dumps({"status": "CONFIRMED", "details": "未经佐证的断言", "evidence": evidence})
    result = c_runner.classify_run(payload, "", 0, target_path="/test/target.c")
    assert result["status"] == "INCONCLUSIVE"
    assert result["evidence"] == evidence
    assert "未经佐证的断言" in result["details"]
    assert "缺少" in result["details"] and "sanitizer" in result["details"]


@pytest.mark.parametrize("diagnostic", [
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 /test/target.c:2:3",
    "/test/target.c:2:3: runtime error: signed integer overflow: 2 + 3",
])
def test_sanitizer_shaped_output_with_success_exit_cannot_confirm(diagnostic):
    result = c_runner.classify_run("", diagnostic, 0, target_path="/test/target.c")
    assert result["status"] == "INCONCLUSIVE"
    assert diagnostic in result["evidence"][0]["content"]
    assert "正常退出" in result["details"]


@pytest.mark.parametrize("language,suffix,compiler", [("c", ".c", "gcc"), ("cpp", ".cpp", "g++")])
def test_real_program_claiming_success_without_calling_target(tmp_path, language, suffix, compiler):
    if not shutil.which(compiler):
        pytest.skip(f"缺少 {compiler}，未运行真实编译验证")
    target = tmp_path / f"target{suffix}"
    target.write_text("int actual_target(void){return 0;}\n")
    evidence = [{"type": "command_output", "content": "假证据：目标已执行"}]
    payload = json.dumps({"status": "CONFIRMED", "details": "未调用目标却声称确认", "evidence": evidence}, ensure_ascii=False)
    source = tmp_path / f"driver{suffix}"
    source.write_text('#include <stdio.h>\nint main(void){puts(' + json.dumps(payload, ensure_ascii=False) + ');return 0;}\n')
    result = c_runner.run_test(source, language, target_filename=target.name)
    assert result["status"] == "INCONCLUSIVE", result
    assert result["evidence"] == evidence


def test_native_not_reproduced_result_remains_unchanged():
    payload = {"status": "NOT_REPRODUCED", "details": "本次输入未复现", "evidence": []}
    assert c_runner.classify_run(json.dumps(payload), "", 0) == payload
