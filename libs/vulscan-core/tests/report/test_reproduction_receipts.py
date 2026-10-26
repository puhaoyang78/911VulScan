"""Reporting-only tests: fake Docker commands, synthetic fixtures, no paid API."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from report import generator
from report.reproduction import fenced, render_reproduction
from utilities.dynamic_tester import docker_executor as executor
from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence as Evidence
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester.reporter import generate_report


GENERATION = {
    "dockerfile": "FROM fixture\nCOPY . /test\nCMD [\"python\", \"proof.py\"]\n",
    "test_script": "# synthetic fixture; not an exploit\nprint('observation')\n",
    "test_filename": "proof.py", "requirements": "fixture==1\n",
    "requirements_filename": "requirements.txt",
}


def test_records_actual_staging_and_commands_without_changing_execution(tmp_path, monkeypatch):
    source = tmp_path / "target.py"
    source.write_text("# controlled target\n", encoding="utf-8")
    calls = []
    payload = json.dumps({"status": "CONFIRMED", "details": "fixture response differs",
                          "evidence": [{"type": "http_response", "content": "fixture HTTP 200"}]})

    def command(argv, timeout, cwd=None, on_output=None):
        calls.append((argv, timeout, cwd))
        if argv[:2] == ["docker", "info"]:
            return "fixture-daemon", "", 0, False
        if argv[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "0B"}), "", 0, False
        return (payload if argv[:2] == ["docker", "run"] else
                "build done" if argv[:2] == ["docker", "build"] else "", "", 0, False)

    monkeypatch.setattr(executor, "_run_command", command)
    execution = executor.run_single_container(GENERATION, "F1", source_file=str(source))
    receipt = execution.reproduction
    assert execution.exit_code == 0 and execution.stdout == payload
    execution_calls = [c for c in calls if c[0][:2] in (["docker", "build"], ["docker", "run"])]
    assert [c[0][:2] for c in execution_calls] == [["docker", "build"], ["docker", "run"]]
    assert any(c[0][:3] == ["docker", "system", "df"] for c in calls)
    assert receipt["cleanup"] == {"ok": True, "errors": []}
    assert [c["argv"] for c in receipt["commands"]] == [c[0] for c in execution_calls]
    assert [c["exit_code"] for c in receipt["commands"]] == [0, 0]
    assert "--network" in receipt["commands"][1]["argv"]
    files = {f["filename"]: f["content"] for f in receipt["artifacts"]}
    assert files == {"Dockerfile": GENERATION["dockerfile"], "proof.py": GENERATION["test_script"],
                     "requirements.txt": "fixture==1\n"}
    assert receipt["source"] == {"filename": source.name,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    assert not Path(execution_calls[0][2]).exists()  # existing cleanup still happens
    result = collect_result({"id": "F1", "identity_key": "stable"}, GENERATION, execution)
    assert result.status == "CONFIRMED"
    assert result.to_dict()["reproduction"] == receipt
    rendered = generate_report([result], "synthetic fixture")
    for value in ("fixture HTTP 200", "--network none", "退出码 0", "非崩溃类漏洞", "proof.py"):
        assert value in rendered


def test_actual_compose_not_unsafe_generated_draft(tmp_path, monkeypatch):
    generation = {**GENERATION, "needs_attacker_server": True, "docker_compose": """
services:
  test:
    build: .
    privileged: true
    volumes: ['/host:/data']
"""}
    monkeypatch.setattr(executor, "_run_command", lambda argv, **kw:
        (json.dumps({"Type": "Build Cache", "Size": "0B"})
         if argv[:3] == ["docker", "system", "df"] else
         "fixture-daemon" if argv[:2] == ["docker", "info"] else "", "", 0, False))
    result = executor.run_single_container(generation, "fixture")
    files = {f["filename"]: f["content"] for f in result.reproduction["artifacts"]}
    assert "privileged" not in files["docker-compose.yml"]
    assert "/host" not in files["docker-compose.yml"]
    assert "no-new-privileges" in files["docker-compose.yml"]
    assert [c["stage"] for c in result.reproduction["commands"]] == ["build", "start", "observe", "cleanup"]
    assert result.reproduction["commands"][-2]["argv"][-4:] == ["logs", "--no-log-prefix", "-f", "test"]
    rendered = render_reproduction(collect_result({"id": "F"}, generation, result).to_dict())
    assert "日志命令退出成功不代表容器或目标执行成功" in rendered


@pytest.mark.parametrize("timed_out,code", [(False, 1), (True, -1)])
def test_build_failure_receipt_is_not_a_runtime_claim(monkeypatch, timed_out, code):
    monkeypatch.setattr(executor, "_run_command", lambda *a, **kw: ("before", "last build error", code, timed_out))
    execution = executor._run_single(".", "fixture", "network", 1, 1)
    result = collect_result({"id": "F"}, GENERATION, execution)
    assert result.status == "ERROR"
    assert len(result.reproduction["commands"]) == 1
    assert result.reproduction["commands"][0]["stage"] == "build"
    assert result.reproduction["commands"][0]["exit_code"] == code
    assert "last build error" in render_reproduction(result.to_dict())


def test_large_logs_are_redacted_and_explicitly_bounded(monkeypatch):
    secret = "sk-" + "x" * 48
    log = secret + "start\n" + "noise\n" * 9000 + "last-diagnostic"
    monkeypatch.setattr(executor, "_run_command", lambda *a, **kw: (log, "", 1, False))
    result = executor._run_single(".", "fixture", "network", 1, 1)
    stored = result.reproduction["commands"][0]["stdout"]
    assert len(stored) <= 12000 and "truncated" in stored and stored.endswith("last-diagnostic")
    assert secret not in stored


def test_absent_receipts_are_not_fabricated_and_poisoned_shapes_do_not_crash():
    legacy = DynamicTestResult("F", "CONFIRMED", "legacy", test_code="legacy script")
    assert "reproduction" not in legacy.to_dict()
    output = render_reproduction(legacy.to_dict())
    assert "未记录测试输出" in output and "构建/运行命令未记录" in output
    assert "legacy script" in output and "退出码 0" not in output
    output = render_reproduction({"status": {"unsafe": "value"}, "evidence": "not-list",
        "reproduction": {"commands": [None, {"stage": {}, "argv": 2}], "artifacts": [42]}})
    assert "未知" in output and "命令参数未记录或格式无效" in output


def test_fences_contain_embedded_markdown_and_do_not_rewrite_code():
    code = "```\n<script>fixture</script>\n````\n"
    block = fenced(code)
    assert block.startswith("`````text\n") and block.endswith("\n`````")
    assert code in block
    output = render_reproduction({"status": "ERROR", "test_code": code})
    assert block in output


def test_merge_keeps_receipts_only_after_identity_match(tmp_path):
    record = {"finding_id": "F", "identity_key": "stable", "status": "ERROR",
              "test_code": "fixture-code", "dockerfile": "fixture-dockerfile",
              "reproduction": {"commands": [{"argv": ["docker", "build", "."]}]}}
    (tmp_path / "dynamic_test_results.json").write_text(json.dumps({"results": [record]}))
    for identity, attached in (("stable", True), ("wrong", False)):
        pipeline = {"findings": [{"id": "F", "identity_key": identity}]}
        generator.merge_dynamic_results(pipeline, str(tmp_path / "pipeline_output.json"))
        block = pipeline["findings"][0].get("dynamic_testing_attempted")
        assert bool(block) == attached
        if attached:
            assert block["reproduction"] == record["reproduction"]
            assert block["test_code"] == "fixture-code"
            assert "dynamic_testing" not in pipeline["findings"][0]


def test_disclosure_inserts_verbatim_receipt_without_sending_it_to_llm():
    from utilities.llm import CompletionResult, PhaseBinding, TextBlock
    prompts = []

    class Adapter:
        def complete(self, **kwargs):
            prompts.append(kwargs["messages"][0].content[0].text)
            return CompletionResult(content=[TextBlock("# 测试披露\n\n静态说明。")],
                                    input_tokens=1, output_tokens=1, stop_reason="end_turn")

    binding = PhaseBinding(phase="report", adapter=Adapter(), model="fixture", provider_name="fixture")
    block = {"status": "NOT_REPRODUCED", "details": "fixture-details",
             "test_code": "UNIQUE_ARTIFACT", "reproduction": {"artifacts": [{"filename": "proof.c",
             "content": "UNIQUE_STAGED_CONTENT"}]}, "evidence": [{"type": "command_output", "content": "UNIQUE_PROOF"}]}
    finding = {"stage2_verdict": "agreed", "dynamic_testing_attempted": block}
    text, _ = generator.generate_disclosure(finding, "fixture", binding)
    assert text.count("### PoC 构建、触发与验证记录") == 1
    assert "UNIQUE_STAGED_CONTENT" in text and "UNIQUE_PROOF" in text
    for value in ("UNIQUE_ARTIFACT", "UNIQUE_STAGED_CONTENT", "UNIQUE_PROOF"):
        assert value not in prompts[0]
    compact = generator._compact_for_summary({"findings": [finding]})
    assert compact["findings"][0]["dynamic_testing_attempted"] == {
        "status": "NOT_REPRODUCED", "details": "fixture-details"}
    assert finding["dynamic_testing_attempted"]["evidence"] == block["evidence"]


def test_checkpoint_resume_preserves_receipt_without_execution(tmp_path, monkeypatch):
    import utilities.dynamic_tester as dynamic
    from utilities.llm_client import TokenTracker
    output = tmp_path / "output"
    checkpoint = output / "dynamic_test_checkpoints"
    checkpoint.mkdir(parents=True)
    receipt = {"commands": [{"stage": "run", "argv": ["docker", "run", "fixture"],
                              "exit_code": 0, "stdout": "saved-observation"}]}
    record = DynamicTestResult("F", "CONFIRMED", "fixture", identity_key="stable", reproduction=receipt,
                               evidence=[Evidence("http_response", "saved-response")]).to_dict()
    record["id"] = "F"  # StepCheckpoint.save stamps the checkpoint lookup key.
    (checkpoint / "F.json").write_text(json.dumps(record))
    pipeline = tmp_path / "pipeline.json"
    pipeline.write_text(json.dumps({"repository": {"name": "fixture"}, "findings": [{
        "id": "F", "identity_key": "stable", "stage2_verdict": "agreed"}]}))
    def forbidden(*args, **kwargs):
        raise AssertionError("resume must not call generation or Docker")
    monkeypatch.setattr(dynamic, "generate_test", forbidden)
    monkeypatch.setattr(dynamic, "run_single_container", forbidden)
    monkeypatch.setattr(dynamic, "get_global_tracker", lambda: TokenTracker())
    restored = dynamic.run_dynamic_tests(str(pipeline), str(output),
        registry=SimpleNamespace(get=lambda phase: object()))
    assert restored[0].reproduction == receipt
    stored = json.loads((output / "dynamic_test_results.json").read_text())["results"][0]
    assert stored["reproduction"] == receipt
