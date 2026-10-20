"""Readable report fields are requested in-place and survive existing parsing.

These checks use synthetic responses only: they do not call a model, run a PoC,
or assert that a model's proposed fix has been tested.
"""

import json

import pytest

from core.analysis_core import parse_response
from prompts.vulnerability_analysis import get_analysis_prompt
from utilities.json_corrector import JSONCorrector, _VULN_SCHEMA


REPORT_FIELDS = {
    "description": "The target reads a value before checking its upper bound.",
    "impact": "A supplied index could cause a read outside the intended array.",
    "remediation": "Reject indices outside [0, count) before the read; test boundaries.",
    "vulnerable_code": "return values[index];",
    "suggested_fix": "if (index >= count) return ERROR;\nreturn values[index];",
}


def test_analysis_prompt_requests_finding_specific_report_content():
    prompt = get_analysis_prompt("return values[index];", "c")
    for field in REPORT_FIELDS:
        assert f'"{field}"' in prompt
        assert f'"{field}"' in _VULN_SCHEMA
    assert "exact excerpt copied from the supplied TARGET function" in prompt
    assert "not tested or an applied patch" in prompt
    assert "If context is insufficient, use null" in prompt
    assert "anticipated impact, not an observed test result" in prompt
    assert "in this same response" in prompt


@pytest.mark.parametrize("verdict", ["vulnerable", "bypassable"])
def test_report_fields_survive_clean_analysis_response(verdict):
    result = parse_response(json.dumps({
        "finding": verdict,
        "reasoning": "Synthetic analysis, not a test execution.",
        **REPORT_FIELDS,
    }))
    assert result["finding"] == verdict
    for key, value in REPORT_FIELDS.items():
        assert result[key] == value


def test_report_fields_survive_json_correction_without_extra_generation(monkeypatch):
    import utilities.json_corrector as corrector

    calls = []

    def extracted(binding, raw, schema=None):
        calls.append((binding, raw, schema))
        return {"finding": "vulnerable", **REPORT_FIELDS}

    monkeypatch.setattr(corrector, "extract_json_with_llm", extracted)
    result = JSONCorrector(binding=None).attempt_correction("synthetic malformed JSON")
    assert len(calls) == 1
    for key, value in REPORT_FIELDS.items():
        assert result[key] == value


def test_legacy_analysis_does_not_fabricate_missing_report_fields():
    result = parse_response('{"finding": "vulnerable", "reasoning": "legacy"}')
    assert result["finding"] == "vulnerable"
    assert all(key not in result for key in REPORT_FIELDS)


def _parse_finish(extra=None, *, original="safe"):
    from utilities.finding_verifier import FindingVerifier

    return FindingVerifier.__new__(FindingVerifier)._parse_finish_result({
        "agree": False,
        "correct_finding": "vulnerable",
        "explanation": "Synthetic code review upgraded the finding; no test ran.",
        **(extra or {}),
    }, original, iterations=1, total_tokens=10)


def test_stage2_finish_report_fields_are_optional_and_schema_aligned():
    from prompts.verification_prompts import get_verification_prompt
    from utilities.finding_verifier import VERIFICATION_TOOLS, _VERIFY_JSON_SCHEMA
    from utilities.json_corrector import _VERIFY_SCHEMA

    finish = next(t for t in VERIFICATION_TOOLS if t["name"] == "finish")
    fields = set(REPORT_FIELDS) - {"vulnerable_code"}
    for field in fields:
        assert field in finish["input_schema"]["properties"]
        assert field not in finish["input_schema"]["required"]
        assert f'"{field}"' in _VERIFY_JSON_SCHEMA
        assert f'"{field}"' in _VERIFY_SCHEMA
    assert "same call" in finish["description"]
    assert "not been applied or tested" in finish["description"]
    prompt = get_verification_prompt("code", "safe", "", "")
    assert "existing finish response" in prompt
    assert "including any correction to Stage 1" in prompt


def test_stage2_upgrade_serializes_its_own_report_content():
    fields = {k: v for k, v in REPORT_FIELDS.items() if k != "vulnerable_code"}
    result = _parse_finish(fields).to_dict()
    assert result["correct_finding"] == "vulnerable"
    assert result["incomplete"] is False
    assert all(result[k] == v for k, v in fields.items())


def test_stage2_legacy_finish_does_not_invent_report_content():
    result = _parse_finish().to_dict()
    assert all(key not in result for key in REPORT_FIELDS)


def test_stage2_explicit_unknown_fix_survives_for_report_fallback():
    result = _parse_finish({"suggested_fix": None}).to_dict()
    assert "suggested_fix" in result
    assert result["suggested_fix"] is None


def test_stage2_malformed_report_field_does_not_change_verdict():
    result = _parse_finish({"impact": {"unexpected": True}, "remediation": 10}).to_dict()
    assert result["correct_finding"] == "vulnerable"
    assert result["incomplete"] is False
    assert "impact" not in result
    assert "remediation" not in result


def test_stage2_incomplete_finish_keeps_report_content_as_nonfinal_provenance():
    # The report consumer must not adopt this as final advice: the incomplete
    # flag remains authoritative, including when a downgrade was withheld.
    result = _parse_finish({
        "agree": True, "correct_finding": "safe", "suggested_fix": None,
    }, original="vulnerable").to_dict()
    assert result["incomplete"] is True
    assert result["correct_finding"] == "vulnerable"
    assert result["withheld_correct_finding"] == "safe"
    assert result["suggested_fix"] is None


def test_report_projection_uses_completed_stage2_content_not_stage1_fix():
    from report.details import finding_fields

    verification = _parse_finish({
        "description": "Stage 2 corrected description",
        "impact": "Stage 2 anticipated impact",
        "remediation": "Stage 2 concrete correction",
        "suggested_fix": "stage2_proposed_fix();",
    }).to_dict()
    fields = finding_fields({
        "finding": "vulnerable", **REPORT_FIELDS, "verification": verification,
    })
    for key in ("description", "impact", "remediation", "suggested_fix"):
        assert fields[key] == verification[key]


@pytest.mark.parametrize("extra", [
    {"agree": False},
    {"agree": True, "consistency_update": {"from": "vulnerable", "to": "bypassable"}},
])
def test_report_projection_does_not_reuse_old_fix_after_reclassification(extra):
    from report.details import finding_fields

    verification = _parse_finish({"agree": extra["agree"]}, original="vulnerable").to_dict()
    row = {"finding": "vulnerable", **REPORT_FIELDS, "verification": verification}
    if "consistency_update" in extra:
        row["consistency_update"] = extra["consistency_update"]
    fields = finding_fields(row)
    assert fields["remediation"] == ""
    assert fields["suggested_fix"] == ""


def test_report_projection_respects_explicit_stage2_unknown_fix():
    from report.details import finding_fields

    verification = _parse_finish({
        "agree": True, "suggested_fix": None,
    }, original="vulnerable").to_dict()
    fields = finding_fields({
        "finding": "vulnerable", **REPORT_FIELDS, "verification": verification,
    })
    assert fields["suggested_fix"] == ""


@pytest.mark.parametrize("workers", [1, 2])
def test_stage2_report_fields_survive_checkpoint_resume(tmp_path, workers):
    from core.checkpoint import StepCheckpoint
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.finding_verifier import FindingVerifier
    from utilities.llm import PhaseBinding

    class Adapter:
        name = "fixture"
        supports_tools = True
        pricing = {}

        def complete(self, **kwargs):
            raise AssertionError("This offline test must never call a model")

    class Verifier(FindingVerifier):
        calls = 0

        def verify_result(self, **kwargs):
            self.calls += 1
            return _parse_finish({
                "description": "Stage 2 upgraded finding",
                "remediation": "Check the upper bound before access.",
                "suggested_fix": None,
            })

        def _check_consistency(self, results, code_by_route):
            return results

    binding = PhaseBinding(
        phase="verify", adapter=Adapter(), model="fixture", provider_name="fixture",
    )
    verifier = Verifier(index=RepositoryIndex({}, repo_path=None), binding=binding)
    checkpoint = StepCheckpoint("verify", str(tmp_path))
    row = {"route_key": "example.c:read_value", "finding": "safe"}
    verifier.verify_batch([row], {}, workers=workers, checkpoint=checkpoint)
    assert verifier.calls == 1
    assert row["finding"] == "vulnerable"
    restored = {"route_key": row["route_key"], "finding": "safe"}
    verifier.verify_batch([restored], {}, workers=workers, checkpoint=checkpoint)
    assert verifier.calls == 1, "A resume must use the saved report content"
    assert restored["finding"] == "vulnerable"
    assert restored["verification"]["remediation"] == "Check the upper bound before access."
    assert restored["verification"]["suggested_fix"] is None
