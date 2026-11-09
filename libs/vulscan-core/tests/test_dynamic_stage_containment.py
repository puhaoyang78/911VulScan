"""动态测试阶段：环境问题跳过整段，单条失败不拖垮整步。"""
import json

import core.dynamic_tester as wrapper
from core.schemas import DynamicTestStepResult, dynamic_test_step_summary
from core.step_report import step_context


def _pipeline(tmp_path):
    path = tmp_path / "pipeline_output.json"
    path.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "findings": [{
            "id": "VULN-001", "name": "X", "identity_key": "k",
            "location": {"file": "a.py", "line": 1},
            "stage2_verdict": "agreed", "verdict": "vulnerable",
        }],
    }), encoding="utf-8")
    return str(path)


def test_environment_failure_skips_whole_stage(tmp_path, monkeypatch):
    import utilities.dynamic_tester as dt

    def unavailable(*args, **kwargs):
        raise dt.DynamicTestUnavailable("Docker 守护进程不可用", "docker_unavailable")

    monkeypatch.setattr(wrapper.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dt, "run_dynamic_tests", unavailable)

    out = tmp_path / "out"
    result = wrapper.run_tests(_pipeline(tmp_path), str(out))

    assert result.skipped_reason == "docker_unavailable"
    assert result.findings_tested == 0
    assert result.errors == 0
    payload = json.loads((out / "dynamic_test_results.json").read_text(encoding="utf-8"))
    assert payload["skipped_reason"] == "docker_unavailable"
    assert payload["results"] == []
    assert "未执行动态测试" in (out / "DYNAMIC_TEST_RESULTS.md").read_text(encoding="utf-8")


def test_unit_executor_exception_becomes_error(monkeypatch):
    import utilities.dynamic_tester as dt

    def boom(*args, **kwargs):
        raise RuntimeError("容器执行器崩了")

    monkeypatch.setattr(dt, "run_single_container", boom)
    execution = dt._run_container_safely({"dockerfile": "x"}, "VULN-001")
    assert "执行器内部错误" in execution.execution_error

    result = dt._collect_safely({"id": "VULN-001"}, {"test_script": "x"}, execution, 0)
    assert result.status == "ERROR"
    assert result.failure_phase == "environment"


def test_summary_keeps_unit_errors_separate():
    result = DynamicTestStepResult(
        results_json_path="x", findings_tested=5, confirmed=2, inconclusive=1,
        errors=2, fatal_error_count=0,
    )
    summary = dynamic_test_step_summary(result)
    assert summary["unit_errors"] == 2
    assert summary["fatal_error_count"] == 0
    assert summary["error_count"] == 2


def _status_after_summary(tmp_path, summary, name):
    out = tmp_path / name
    out.mkdir()
    with step_context("dynamic-test", str(out)) as ctx:
        ctx.summary = summary
    data = json.loads((out / "dynamic-test.report.json").read_text(encoding="utf-8"))
    return data["status"]


def test_unit_errors_do_not_make_step_partial(tmp_path):
    assert _status_after_summary(tmp_path, {
        "fatal_error_count": 0, "unit_errors": 2, "findings_tested": 5,
        "error_count": 2,
    }, "few") == "success"


def test_stage_failure_makes_step_partial(tmp_path):
    assert _status_after_summary(tmp_path, {
        "fatal_error_count": 1, "unit_errors": 0, "findings_tested": 5,
        "error_count": 0,
    }, "fatal") == "partial"


def test_majority_unit_errors_make_step_partial(tmp_path):
    assert _status_after_summary(tmp_path, {
        "fatal_error_count": 0, "unit_errors": 4, "findings_tested": 5,
        "error_count": 4,
    }, "many") == "partial"
