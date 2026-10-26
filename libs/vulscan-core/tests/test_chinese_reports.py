# Modified 2026-10-23 for the VulScan-only product namespace.
"""Chinese report surfaces preserve protocol identities and security boundaries."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from context.application_context import ApplicationContext
from prompts import vulnerability_analysis, verification_prompts
from prompts.report_language import CHINESE_REPORT_INSTRUCTION
from report import generator
from report.localization import display_label
from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence as Evidence
from utilities.dynamic_tester.reporter import generate_report


@pytest.mark.parametrize("context", [None, ApplicationContext(application_type="cli_tool", purpose="fixture"), ApplicationContext(application_type="library", purpose="fixture", trust_boundaries={"input_files": "untrusted"})])
def test_analysis_and_verification_require_chinese_without_translating_schema(context):
    for prompt in (vulnerability_analysis.get_system_prompt(context), verification_prompts.get_verification_system_prompt(context)):
        assert CHINESE_REPORT_INSTRUCTION in prompt
        assert "Simplified Chinese" in prompt
        assert "Keep JSON keys" in prompt
    user = vulnerability_analysis.get_analysis_prompt("def f(): pass", "python", app_context=context)
    assert '"finding": "safe" | "protected" | "vulnerable" | "inconclusive"' in user
    assert "def f(): pass" in user


def test_consistency_prompt_also_requires_chinese():
    assert CHINESE_REPORT_INSTRUCTION in verification_prompts.get_consistency_check_prompt([], {})


@pytest.mark.parametrize("verdict,label", [("CONFIRMED", "复核保留"), ("ERROR", "错误"), ("NOT_REPRODUCED", "未复现"), ("critical", "严重"), ("unknown", "未知")])
def test_display_enum_mapping(verdict, label):
    assert display_label(verdict) == label
    assert display_label("CWE-79") == "CWE-79"


def test_summary_tables_and_verification_dimensions_are_chinese():
    data = {"pipeline_stats": {"parsed_units": 12, "durations": {"verify": 10.22}, "costs": {"verify": {"actual": 0.0}}}, "results": {"vulnerable": 1, "errors": 0}, "findings": [{"name": "路径穿越", "location": {"file": "src/main.c", "function": "load"}, "cwe_id": 22, "severity": "high", "stage1_verdict": "vulnerable", "stage2_verdict": "confirmed", "dynamic_testing_attempted": {"status": "ERROR"}}]}
    before = deepcopy(data)
    text = generator._summary_statistics_block(data) + generator._summary_tables_block(data)
    for expected in ("已解析：12", "模型复核", "10.2s", "$0.00", "复核保留的漏洞", "高危", "动态测试：测试错误", "src/main.c:load", "CWE-22"):
        assert expected in text
    header = generator._disclosure_verdict_header(data["findings"][0])
    assert "复核保留" in header
    assert "测试错误" in header
    assert "已复现" not in header
    for english in ("## Pipeline Statistics", "## Results", "## Confirmed Vulnerabilities", "| Severity |", "**Verification:**", "dynamic test failed"):
        assert english not in text + header
    assert data == before


def test_chinese_server_sections_and_code_splice_are_deduplicated():
    text = "# 报告\n\n## 分析方法\n\n伪造信息\n\n## 扫描结果\n\n999\n\n## 覆盖范围\n\n保留内容\n"
    stripped = generator._strip_server_sections(text)
    assert "伪造信息" not in stripped and "999" not in stripped
    assert "保留内容" in stripped
    code = "## 漏洞代码\n\n```c\nchar *p = input;\n```"
    disclosure = "# 披露\n\n## 漏洞代码\n\n伪造代码\n\n## 复现步骤\n\n调用 load。\n"
    result = generator._splice_code_section(disclosure, code)
    assert result.count("## 漏洞代码") == 1 and "伪造代码" not in result
    assert result.index("char *p = input;") < result.index("## 复现步骤")


def test_dynamic_report_translates_labels_preserving_evidence_and_machine_status():
    result = DynamicTestResult("VULN-001", "CONFIRMED", "已读取测试文件。", evidence=[Evidence("file_read", "/tmp/fixture.txt")], test_code="print('CONFIRMED')")
    before = result.to_dict()
    text = generate_report([result], repo_name="fixture")
    for expected in ("动态测试结果", "已复现", "文件读取", "/tmp/fixture.txt", "print('CONFIRMED')", "VULN-001"):
        assert expected in text
    for english in ("# Dynamic Test Results", "## Summary", "**Status:**", "**Evidence:**", "Generated Test Code"):
        assert english not in text
    assert result.to_dict() == before


class CapturingAdapter:
    def __init__(self):
        self.calls = []

    def complete(self, **kwargs):
        from utilities.llm import TextBlock
        self.calls.append(kwargs)
        return SimpleNamespace(content=[TextBlock("# 测试报告\n\n## 覆盖范围\n\n已分析。\n")], input_tokens=1, output_tokens=2, usage_details=None, stop_reason="end_turn")


def test_generated_reports_explicitly_request_chinese(monkeypatch):
    adapter = CapturingAdapter()
    binding = SimpleNamespace(adapter=adapter, model="fixture", provider_name="fixture")
    monkeypatch.setattr(generator, "lookup_pricing", lambda _: {"input": 1, "output": 1})
    generator.generate_summary_report({"repository": {"name": "fixture"}, "findings": []}, binding)
    generator.generate_disclosure({"stage2_verdict": "confirmed", "location": {"file": "src/main.c"}}, "fixture", binding)
    for call in adapter.calls:
        assert "Simplified Chinese" in call["system"]
        assert "Preserve code" in call["system"]
        assert CHINESE_REPORT_INSTRUCTION in call["system"]
        assert "不要在每节重复" in call["system"]
    assert "## 覆盖范围" in adapter.calls[0]["messages"][0].content[0].text
    assert "## 复现步骤" in adapter.calls[1]["messages"][0].content[0].text


def test_attacker_descriptor_is_chinese_and_keeps_kind():
    descriptor = verification_prompts.attacker_model_descriptor(None)
    assert descriptor["kind"] == "browser_only"
    assert "远程攻击者" in descriptor["attacker"]


def test_report_data_chinese_fallback_preserves_json_contract(tmp_path, capsys):
    import json
    from vulscan.cli import cmd_report_data, _remediation_for_unrecognized

    results = tmp_path / "results.json"
    dataset = tmp_path / "dataset.json"
    results.write_text(json.dumps({"results": [{"route_key": "src/main.c:main", "finding": "safe", "reasoning": "未发现安全敏感操作。"}]}), encoding="utf-8")
    dataset.write_text(json.dumps({"units": []}), encoding="utf-8")
    assert cmd_report_data(SimpleNamespace(results=str(results), dataset=str(dataset))) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "success"
    data = payload["data"]
    assert data["title"] == "安全分析报告"
    assert "没有可直接生成修复建议的漏洞" in data["remediation_html"]
    assert "所有函数均安全" not in data["remediation_html"]
    assert "代码存在可利用的安全漏洞" in data["categories"][0]["description"]
    assert data["findings"][0]["verdict"] == "safe"
    assert data["unit_chart"]["labels"] == ["safe"]
    fallback = _remediation_for_unrecognized([], [{"verdict": "error"}, {"verdict": "unknown"}])
    assert "1 个分析出错" in fallback and "1 个结论无法识别" in fallback
    assert "未发现漏洞" not in fallback


def test_empty_and_warning_report_fallbacks_have_chinese_headings():
    fallback = generator._summary_methodology_block({}) + generator._summary_tables_block({"findings": []})
    warning = generator._context_provenance_header({"context_source": "threat_model"})
    assert "## 分析方法" in fallback and "没有可报告的漏洞" in fallback
    assert "安全模型来自仓库控制的文件" in warning
    for english in ("## Methodology", "No findings to report", "Attacker model:", "Security model supplied"):
        assert english not in fallback + warning


def test_report_prompts_do_not_reintroduce_obsolete_verification_wording():
    summary = generator.load_prompt("summary")
    disclosure = generator.load_prompt("disclosure")
    assert "Stage 2 attacker simulation passed" not in summary
    assert '"verified" if stage2_verdict' not in summary
    assert "model agreement as successful dynamic reproduction" in summary
    assert "最近一次分析结论" in summary
    assert "验证方式：{" not in disclosure
    assert "without a confirmed dynamic result" in disclosure.lower()
    assert "建议复现步骤（未测试）" in disclosure


@pytest.mark.parametrize("findings,expected", [
    ([], "当前结果没有可直接生成修复建议的漏洞"),
    ([{"verdict": "safe"}], "当前结果没有可直接生成修复建议的漏洞"),
    ([{"verdict": "error"}], "1 项分析未完成"),
])
def test_legacy_html_empty_remediation_does_not_claim_everything_is_safe(findings, expected):
    from report.html_report import generate_remediation_guidance
    text = generate_remediation_guidance(findings)
    assert expected in text
    assert "均安全" not in text and "已确认" not in text
