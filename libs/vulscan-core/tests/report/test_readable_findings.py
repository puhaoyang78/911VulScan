# Modified 2026-10-23 for the VulScan-only product namespace.
"""Readable report projection: no network, model calls or PoC execution."""

import csv
import json
from types import SimpleNamespace

import pytest

from core.reporter import build_pipeline_output, finding_identity_key
from vulscan import cli
from report.csv_export import export_csv
from report.details import dynamic_for_result, finding_fields, load_dynamic_by_route
from report.schema import Finding


def _write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _fixture(tmp_path):
    result = {
        "route_key": "fixture.c:lookup", "finding": "vulnerable",
        "cwe_id": 125, "cwe_name": "越界读取",
        "reasoning": "fixture reasoning", "description": "索引未经范围检查。",
        "impact": ["可能读取数组范围外的数据。"], "remediation": "访问前检查边界。",
        "suggested_fix": "if (index >= count) return ERROR;",
        "verification": {"agree": True, "explanation": "模型复核说明，未执行代码。"},
    }
    results, dataset = tmp_path / "results.json", tmp_path / "dataset.json"
    _write(results, {"results": [result], "code_by_route": {"fixture.c:lookup": "return data[index];"}})
    _write(dataset, {"units": [{"id": "fixture.c:lookup", "code": {"primary_code": "return data[index];"}}]})
    build_pipeline_output(str(results), str(tmp_path / "pipeline_output.json"), repo_name="SYNTHETIC-NOT-EXECUTED")
    identity = finding_identity_key("fixture.c", "lookup", 125)
    _write(tmp_path / "dynamic_test_results.json", {"results": [{
        "finding_id": "VULN-001", "identity_key": identity, "status": "ERROR",
        "details": "SYNTHETIC fixture: test environment unavailable; no target execution.",
        "test_code": "// Synthetic saved artifact, never executed",
        "evidence": [],
    }]})
    return result, results, dataset


def test_new_fields_survive_pipeline_and_optional_schema(tmp_path):
    _, _, _ = _fixture(tmp_path)
    finding = json.loads((tmp_path / "pipeline_output.json").read_text())["findings"][0]
    assert finding["description"] == "索引未经范围检查。"
    assert finding["impact"] == "可能读取数组范围外的数据。"
    assert finding["remediation"] == "访问前检查边界。"
    assert finding["suggested_fix_status"] == "proposed_unvalidated"
    assert finding["vulnerable_code"] == "return data[index];"
    assert Finding.from_dict(finding).remediation == "访问前检查边界。"
    for key in ("remediation", "suggested_fix_status"):
        finding.pop(key)
    assert Finding.from_dict(finding).suggested_fix_status is None


def test_stage2_details_override_and_do_not_revive_stale_fixes():
    original = {"description": "old", "impact": "old impact", "remediation": "old remedy", "suggested_fix": "old code"}
    assert finding_fields(original)["suggested_fix"] == "old code"
    revised = {**original, "verification": {"agree": False, "explanation": "different issue"}}
    assert finding_fields(revised)["description"] == "different issue"
    assert finding_fields(revised)["suggested_fix"] == ""
    assert finding_fields(revised)["impact"] == ""
    revised["verification"].update(remediation="new remedy", suggested_fix="new code")
    assert finding_fields(revised)["suggested_fix"] == "new code"
    revised["verification"]["suggested_fix"] = None
    assert finding_fields(revised)["suggested_fix"] == ""
    revised["verification"]["agree"] = True
    assert finding_fields(revised)["suggested_fix"] == ""
    revised["consistency_update"] = {"from": "vulnerable", "to": "bypassable"}
    assert finding_fields(revised)["remediation"] == ""


def test_legacy_nested_and_malformed_values_are_readable():
    fields = finding_fields({"vulnerabilities": [None, {"description": "legacy", "impact": ["a", "b"], "suggested_fix": "fix"}]})
    assert fields["description"] == "legacy" and fields["impact"] == "a\nb"
    fields = finding_fields({"verification": "bad", "description": {"text": "why"}, "vulnerabilities": 42})
    assert json.loads(fields["description"]) == {"text": "why"}
    assert "未记录" in fields["stage2_verification"]


def test_dynamic_identity_checks_all_three_records(tmp_path):
    result, results, _ = _fixture(tmp_path)
    joined = load_dynamic_by_route(str(results))
    assert dynamic_for_result(result, joined)["status"] == "ERROR"
    assert dynamic_for_result({**result, "cwe_id": 79}, joined) == {}
    pipeline = json.loads((tmp_path / "pipeline_output.json").read_text())
    pipeline["findings"][0]["identity_key"] = "different-scan"
    _write(tmp_path / "pipeline_output.json", pipeline)
    assert load_dynamic_by_route(str(results)) == {}
    pipeline["findings"][0].pop("identity_key")
    _write(tmp_path / "pipeline_output.json", pipeline)
    assert load_dynamic_by_route(str(results)) == {}


@pytest.mark.parametrize("cwe", [None, "", 0, "unknown", -1])
def test_missing_or_invalid_cwe_never_authenticates_dynamic_result(cwe):
    result = {"route_key": "fixture.c:lookup", "finding": "vulnerable", "cwe_id": cwe}
    record = {"status": "CONFIRMED", "identity_key": finding_identity_key("fixture.c", "lookup", cwe)}
    assert dynamic_for_result(result, {"fixture.c:lookup": record}) == {}


@pytest.mark.parametrize("sidecar", ["dynamic_test_results.json", "pipeline_output.json"])
def test_invalid_optional_sidecars_do_not_block_static_csv(tmp_path, capsys, sidecar):
    _, results, dataset = _fixture(tmp_path)
    (tmp_path / sidecar).write_text('{"results": [', encoding="utf-8")
    output = tmp_path / "report.csv"
    export_csv(str(results), str(dataset), str(output))
    with output.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["description"] == "索引未经范围检查。"
    assert row["dynamic_test_status"] == "" and row["reproduction"] == ""
    assert "动态测试输出未关联" in capsys.readouterr().err


def test_unreadable_optional_evidence_warns_without_claiming_no_test(tmp_path, monkeypatch, capsys):
    _, results, _ = _fixture(tmp_path)
    from report import details

    def unreadable(_):
        raise PermissionError("fixture denied")

    monkeypatch.setattr(details, "read_json", unreadable)
    assert load_dynamic_by_route(str(results)) == {}
    warning = capsys.readouterr().err
    assert "动态测试输出未关联" in warning and "PermissionError" in warning


def test_live_report_data_and_csv_keep_full_details_without_api(tmp_path, monkeypatch, capsys):
    result, results, dataset = _fixture(tmp_path)
    result["verification"]["explanation"] = "说明" * 300 + "仅在特定条件下成立。"
    result["remediation"] = '=HYPERLINK("untrusted")'
    _write(results, {"results": [result]})
    # Suppress only the existing summary-remediation model call.
    monkeypatch.setattr(cli, "_remediation_for_unrecognized", lambda *_: "<p>合成离线样例；未执行 PoC。</p>")
    assert cli.cmd_report_data(SimpleNamespace(results=str(results), dataset=str(dataset))) == 0
    payload = json.loads(capsys.readouterr().out)
    finding = payload["data"]["findings"][0]
    assert finding["cwe_id"] == "125"
    assert finding["analysis"].endswith("仅在特定条件下成立。")
    assert finding["vulnerable_code"] == "return data[index];"
    assert finding["dynamic_test_status"] == "ERROR"
    assert "构建/运行命令未记录" in finding["reproduction"]
    assert finding["stage2_verification"].startswith("模型复核：结论一致。")
    assert "已复现" not in finding["stage2_verification"]
    output = tmp_path / "report.csv"
    export_csv(str(results), str(dataset), str(output))
    with output.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["remediation"].startswith("'=")
    assert row["stage2_verdict"] == "vulnerable"  # backward-compatible final verdict
    assert row["suggested_fix_status"] == "proposed_unvalidated"
    assert row["dynamic_test_status"] == "ERROR"
    assert "未记录命令退出码、标准输出和标准错误" in row["reproduction"]


@pytest.mark.parametrize("renderer", ["cli", "legacy"])
def test_remediation_uses_thinking_budget_and_preserves_findings(
        tmp_path, monkeypatch, capsys, renderer):
    import utilities.llm as llm
    from report import html_report

    _, results, dataset = _fixture(tmp_path)
    original = results.read_bytes()
    calls = []

    def complete(**request):
        calls.append(request)
        # Deterministic provider fixture: the old 4096 cap cannot finish.
        if request["max_tokens"] < llm.DEFAULT_MAX_TOKENS:
            raise llm.LLMResponseError(
                "输出上限不足", stop_reason="max_tokens", output_tokens=4096)
        return llm.CompletionResult(
            content=(llm.TextBlock("<p>检查 #1 的数组索引范围。</p>"),),
            stop_reason="end_turn", input_tokens=10, output_tokens=6000)

    adapter = SimpleNamespace(
        name="deepseek", complete=complete,
        pricing={"deepseek-flash": {"input": 0.3, "output": 1.2}})
    binding = llm.PhaseBinding(
        phase="report", adapter=adapter, model="deepseek-flash",
        provider_name="custom-deepseek")
    registry = SimpleNamespace(get=lambda phase: binding)
    for module in (llm, html_report):
        monkeypatch.setattr(module, "load_config_file", lambda: object())
        monkeypatch.setattr(module, "resolve_llm_config", lambda *_: object())
        monkeypatch.setattr(module, "build_phase_registry", lambda *_: registry)
    monkeypatch.setattr(html_report, "probe_registry_or_raise", lambda *_: None)

    if renderer == "cli":
        assert cli.cmd_report_data(SimpleNamespace(
            results=str(results), dataset=str(dataset))) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["findings"][0]["cwe_id"] == "125"
        assert payload["findings"][0]["dynamic_test_status"] == "ERROR"
        assert 'href="#finding-1"' in payload["remediation_html"]
        step = json.loads((tmp_path / "report-data.report.json").read_text())
        assert step["token_usage"]["output_tokens"] == 6000
    else:
        output = html_report.generate_remediation_guidance([{
            "unit_id": "fixture.c:lookup", "verdict": "vulnerable",
            "attack_vector": "数组索引", "stage2_explanation": "边界检查缺失",
            "stage1_reasoning": "边界检查缺失"}])
        assert "数组索引" in output

    assert results.read_bytes() == original
    assert len(calls) == 1
    assert calls[0]["max_tokens"] == llm.DEFAULT_MAX_TOKENS


@pytest.mark.parametrize("ceiling,expected", [
    (None, 20000), (4096, 4096), (16384, 16384), (393216, 20000),
])
def test_report_budget_respects_native_provider_model_limit(monkeypatch, ceiling, expected):
    from core import model_registry
    from report.generator import report_max_tokens

    def limit(provider, model):
        assert (provider, model) == ("deepseek", "model")
        return ceiling

    monkeypatch.setattr(model_registry, "max_output_tokens", limit)
    binding = SimpleNamespace(
        adapter=SimpleNamespace(name="deepseek"), model="model",
        provider_name="custom-deepseek")
    assert report_max_tokens(binding) == expected


@pytest.mark.parametrize("empty_response", [False, True])
def test_rejected_summary_records_billed_usage_without_creating_report(tmp_path, monkeypatch, empty_response):
    from core import reporter
    import utilities.llm_client as client
    from utilities.llm import CompletionResult, LLMResponseError, PhaseBinding, TextBlock

    _fixture(tmp_path)
    tracker = client.TokenTracker()
    monkeypatch.setattr(client, "_global_tracker", tracker)

    def complete(**kwargs):
        if empty_response:
            return CompletionResult(content=(TextBlock(" \n "),), stop_reason="max_tokens",
                                    input_tokens=10, output_tokens=20000, usage_details={"cached_tokens": 5})
        raise LLMResponseError("输出上限不足", input_tokens=10, output_tokens=20000,
                               usage_details={"cached_tokens": 5}, stop_reason="max_tokens")

    binding = PhaseBinding(phase="report", model="fixture", provider_name="fixture",
                           adapter=SimpleNamespace(complete=complete, name="fixture",
                                                   pricing={"fixture": {"input": 1, "output": 2}}))
    registry = SimpleNamespace(get=lambda _: binding)
    output = tmp_path / "summary.md"
    with pytest.raises(LLMResponseError, match="生成为空" if empty_response else "输出上限"):
        reporter.generate_summary_report(str(tmp_path / "pipeline_output.json"), str(output), registry=registry)
    totals = tracker.get_totals()
    assert totals["total_calls"] == 1
    assert totals["total_output_tokens"] == 20000
    assert not output.exists()


@pytest.mark.parametrize("fail_second", [False, True])
def test_each_disclosure_call_is_recorded_even_when_batch_fails(tmp_path, monkeypatch, fail_second):
    from core import reporter
    from threading import Event
    import utilities.llm_client as client
    from utilities.llm import CompletionResult, LLMResponseError, PhaseBinding, TextBlock

    _fixture(tmp_path)
    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline = json.loads(pipeline_path.read_text())
    first = pipeline["findings"][0]
    pipeline["findings"].append({**first, "id": "VULN-002", "short_name": "SECOND",
                                  "location": {**first["location"], "function": "second"}})
    _write(pipeline_path, pipeline)
    tracker = client.TokenTracker()
    monkeypatch.setattr(client, "_global_tracker", tracker)
    started = Event()

    def complete(**request):
        prompt = request["messages"][0].content[0].text
        if '"function": "second"' in prompt:
            assert started.wait(2)
            if fail_second:
                raise LLMResponseError("第二份报告响应无效", input_tokens=20, output_tokens=20000)
            return CompletionResult(content=(TextBlock("## 影响\n第二份报告。"),),
                                    stop_reason="end_turn", input_tokens=20, output_tokens=20000)
        started.set()
        Event().wait(0.1)  # The other call fails while this call is in flight.
        return CompletionResult(content=(TextBlock("## 影响\n已保存的第一份报告。"),),
                                stop_reason="end_turn", input_tokens=10, output_tokens=100)

    binding = PhaseBinding(phase="report", model="fixture", provider_name="fixture",
                           adapter=SimpleNamespace(complete=complete, name="fixture",
                                                   pricing={"fixture": {"input": 1, "output": 2}}))
    registry = SimpleNamespace(get=lambda _: binding)
    output = tmp_path / "reports"
    if fail_second:
        with pytest.raises(LLMResponseError, match="第二份报告"):
            reporter.generate_disclosure_docs(str(pipeline_path), str(output), registry=registry)
    else:
        result = reporter.generate_disclosure_docs(str(pipeline_path), str(output), registry=registry)
        assert result.usage.total_calls == 2
    totals = tracker.get_totals()
    assert totals["total_calls"] == 2
    assert totals["total_input_tokens"] == 30
    assert totals["total_output_tokens"] == 20100
    assert len(list(output.glob("*.md"))) == (1 if fail_second else 2)


def test_unknown_and_skipped_dynamic_rows_remain_in_grouped_html(tmp_path, monkeypatch, capsys):
    _, results, dataset = _fixture(tmp_path)
    data = json.loads(results.read_text())
    other = {**data["results"][0], "route_key": "fixture.c:second"}
    data["results"].append(other)
    _write(results, data)
    build_pipeline_output(str(results), str(tmp_path / "pipeline_output.json"))
    _write(tmp_path / "dynamic_test_results.json", {"results": [
        {"finding_id": "VULN-001", "identity_key": finding_identity_key("fixture.c", "lookup", 125), "status": "SKIPPED"},
        {"finding_id": "VULN-002", "identity_key": finding_identity_key("fixture.c", "second", 125), "status": ["bad"]},
    ]})
    monkeypatch.setattr(cli, "_remediation_for_unrecognized", lambda *_: "synthetic")
    assert cli.cmd_report_data(SimpleNamespace(results=str(results), dataset=str(dataset))) == 0
    groups = json.loads(capsys.readouterr().out)["data"]["findings_by_verdict"]
    rows = [f for group in groups for sub in group["subgroups"] for f in sub["findings"]]
    assert {f["dynamic_test_status"] for f in rows} == {"SKIPPED", "UNKNOWN"}


def test_report_projection_no_llm_preserves_original_step_records(tmp_path, monkeypatch, capsys):
    import utilities.llm
    _, results, dataset = _fixture(tmp_path)
    original = tmp_path / 'report-data.report.json'
    original.write_text('{"cost_usd":1.5,"status":"success"}')
    before = {p.name:p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    def forbidden(*args, **kwargs):
        raise AssertionError('read-only report projection called a model')
    monkeypatch.setattr(utilities.llm, 'simple_text', forbidden)
    assert cli.cmd_report_data(SimpleNamespace(results=str(results),dataset=str(dataset),no_llm=True))==0
    data = json.loads(capsys.readouterr().out)['data']
    assert data['findings'][0]['cwe_id']=='125'
    assert data['remediation_html']==''
    assert {p.name:p.read_bytes() for p in tmp_path.iterdir() if p.is_file()} == before
