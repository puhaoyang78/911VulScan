"""C/C++ 固定模板的标准库链接和超时诊断回归；仅执行受控样例。"""

import json
import shutil
import subprocess

import pytest

from utilities.dynamic_tester.docker_templates import c_runner


@pytest.mark.parametrize("language,suffix,compiler", [
    ("c", ".c", "gcc"), ("cpp", ".cpp", "g++"),
])
def test_real_standard_math_library(tmp_path, language, suffix, compiler):
    if not shutil.which(compiler):
        pytest.skip(f"缺少 {compiler}，未运行真实编译验证")
    target = tmp_path / f"target{suffix}"
    target.write_text("#include <math.h>\ndouble compute(double x) { return sqrt(x); }\n")
    source = tmp_path / f"driver{suffix}"
    payload = {"status": "NOT_REPRODUCED", "details": "标准库计算完成", "evidence": []}
    literal = json.dumps(json.dumps(payload, ensure_ascii=False), ensure_ascii=False)
    source.write_text(f'#include "{target.name}"\n#include <stdio.h>\n'
                      'int main(void) { volatile double x = 9.0; '
                      'if (compute(x) != 3.0) return 2; '
                      f'puts({literal}); return 0; }}\n', encoding="utf-8")
    assert c_runner.run_test(source, language, target_filename=target.name) == payload


@pytest.mark.parametrize("stage,status", [("compile", "ERROR"), ("runtime", "INCONCLUSIVE")])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_timeout_retains_captured_diagnostics(tmp_path, monkeypatch, stage, status, as_bytes):
    source = tmp_path / "driver.c"
    source.write_text("int main(void) { return 0; }\n")
    stdout = "测试步骤已开始"
    stderr = "依赖诊断：最后一条错误"
    if as_bytes:
        stdout = stdout.encode("utf-8") + b"\xe4"
        stderr = stderr.encode("utf-8") + b"\xff"

    def fake_run(command, **kwargs):
        if stage == "runtime" and command[0] == "gcc":
            return subprocess.CompletedProcess(command, 0, "", "")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=stdout, stderr=stderr)

    monkeypatch.setattr(c_runner.subprocess, "run", fake_run)
    result = c_runner.run_test(source, "c")
    assert result["status"] == status
    assert "超时" in result["details"]
    contents = [e["content"] for e in result["evidence"]]
    assert "依赖诊断：最后一条错误" in contents[0]
    assert "测试步骤已开始" in contents[1]
    if as_bytes:
        assert all(content.endswith("\ufffd") for content in contents)
    json.dumps(result, ensure_ascii=False)  # The standalone runner must emit JSON, never bytes.


def test_compile_timeout_preserves_last_diagnostic_with_existing_budget(tmp_path, monkeypatch):
    source = tmp_path / "driver.c"
    source.write_text("int main(void) { return 0; }\n")
    output = "前置诊断\n" + "warning\n" * 3000 + "final_link_error: 缺失符号\n"

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr=output.encode("utf-8"))

    monkeypatch.setattr(c_runner.subprocess, "run", fake_run)
    result = c_runner.run_test(source, "c")
    assert result["status"] == "ERROR"
    diagnostic = result["evidence"][0]["content"]
    assert len(diagnostic) <= 12000
    assert diagnostic.startswith("前置诊断")
    assert diagnostic.endswith("final_link_error: 缺失符号\n")


def test_real_runtime_timeout_retains_flushed_output(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("缺少 GCC，未运行真实编译验证")
    source = tmp_path / "driver.c"
    source.write_text('#include <stdio.h>\n'
                      'int main(void) { fputs("等待目标返回\\n", stderr); '
                      'fflush(stderr); for (;;) {} }\n', encoding="utf-8")
    result = c_runner.run_test(source, "c", timeout=0.2)
    assert result["status"] == "INCONCLUSIVE", result
    assert "超时" in result["details"]
    assert "等待目标返回" in result["evidence"][0]["content"]
