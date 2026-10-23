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
    assert "动态证据未关联" in capsys.readouterr().err


def test_unreadable_optional_evidence_warns_without_claiming_no_test(tmp_path, monkeypatch, capsys):
    _, results, _ = _fixture(tmp_path)
    from report import details

    def unreadable(_):
        raise PermissionError("fixture denied")

    monkeypatch.setattr(details, "read_json", unreadable)
    assert load_dynamic_by_route(str(results)) == {}
    warning = capsys.readouterr().err
    assert "动态证据未关联" in warning and "PermissionError" in warning


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
    assert "崩溃已复现" in finding["stage2_verification"]  # explicitly NOT equivalent
    output = tmp_path / "report.csv"
    export_csv(str(results), str(dataset), str(output))
    with output.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["remediation"].startswith("'=")
    assert row["stage2_verdict"] == "vulnerable"  # backward-compatible final verdict
    assert row["suggested_fix_status"] == "proposed_unvalidated"
    assert row["dynamic_test_status"] == "ERROR"
    assert "未保留命令级退出状态" in row["reproduction"]


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
