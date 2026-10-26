"""靶场/教学仓库：自动识别、上下文标记与两个阶段提示词的行为。"""

from pathlib import Path
import pytest

from context.application_context import (
    ApplicationContext,
    stamp_intentional_vulnerability,
)
from context.intentional import detect_intentional_vulnerabilities


def _repo(tmp_path: Path, readme: str, name: str = "app") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "README.md").write_text(readme, encoding="utf-8")
    return root


def test_readme_declaring_intent_is_detected(tmp_path):
    root = _repo(tmp_path, "# Demo\n\nThis application is deliberately vulnerable for training.\n")
    detected, evidence = detect_intentional_vulnerabilities(root)
    assert detected is True
    assert any("README.md" in item for item in evidence)


def test_repository_name_signal_is_detected(tmp_path):
    root = _repo(tmp_path, "# nothing here\n", name="vulnerable-node-api")
    detected, evidence = detect_intentional_vulnerabilities(root)
    assert detected is True
    assert any("目录名" in item for item in evidence)


def test_ordinary_project_is_not_flagged(tmp_path):
    root = _repo(tmp_path, "# Payments API\n\nWe follow OWASP ASVS and review every release.\n")
    assert detect_intentional_vulnerabilities(root) == (False, [])


@pytest.mark.parametrize("value", ["false", 0, None, []])
def test_teaching_scope_rejects_non_boolean_values(value):
    with pytest.raises(ValueError, match="deliberately_vulnerable"):
        ApplicationContext(application_type="web_app", purpose="app", deliberately_vulnerable=value)


def test_teaching_detection_does_not_follow_readme_symlinks(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    external = tmp_path / "outside.md"
    external.write_text("deliberately vulnerable")
    (root / "README.md").symlink_to(external)
    assert detect_intentional_vulnerabilities(root) == (False, [])


def test_teaching_policy_change_does_not_reuse_the_previous_analysis():
    from types import SimpleNamespace
    from core.analyzer import _analyze_fingerprint

    binding = SimpleNamespace(phase="analyze", model="fixture", provider_name="fixture",
                              adapter=SimpleNamespace(name="fixture"))
    normal = _analyze_fingerprint(binding)
    assert normal["key_digest"] == _analyze_fingerprint(binding, intentional=False)["key_digest"]
    assert normal["key_digest"] != _analyze_fingerprint(binding, intentional=True)["key_digest"]


def test_educational_use_alone_does_not_disable_normal_security_scope(tmp_path):
    root = _repo(tmp_path, "An ordinary tutorial application for educational purposes.\n")
    assert detect_intentional_vulnerabilities(root) == (False, [])


def test_all_prompt_paths_keep_demo_behaviors_reportable():
    from context.application_context import format_context_for_prompt
    from prompts.vulnerability_analysis import format_app_context_for_prompt
    from prompts.verification_prompts import format_app_context_for_verification

    context = ApplicationContext(application_type="web_app", purpose="practice",
        deliberately_vulnerable=True, intended_behaviors=["SQL injection teaching feature"],
        not_a_vulnerability=["SQL injection is intentional"])
    for render in (format_context_for_prompt, format_app_context_for_prompt,
                   format_app_context_for_verification):
        prompt = render(context)
        assert "SQL injection teaching feature" in prompt
        assert "FEATURES, not vulnerabilities" not in prompt
        assert "Do NOT flag" not in prompt


def test_manual_context_still_applies_operator_teaching_flag(tmp_path, monkeypatch):
    import context.application_context as app
    root = _repo(tmp_path, "An ordinary app without classification signals.\n")
    manual = ApplicationContext(application_type="web_app", purpose="app", source="manual")
    monkeypatch.setattr(app, "check_manual_override", lambda path: manual)
    result = app.generate_application_context(root, object(), include_intentional=True)
    assert result.deliberately_vulnerable is True
    assert "--include-intentional" in result.intent_note()


def test_stamp_marks_context_and_keeps_evidence(tmp_path):
    root = _repo(tmp_path, "This is a CTF challenge.\n")
    context = ApplicationContext(application_type="web_app", purpose="demo")
    stamp = stamp_intentional_vulnerability(context, root)
    assert stamp.deliberately_vulnerable is True
    assert stamp.deliberate_vulnerability_evidence
    assert "仍" not in stamp.intent_note() or "真实漏洞" in stamp.intent_note()


def test_force_flag_covers_repositories_without_docs(tmp_path):
    root = _repo(tmp_path, "no signal here\n")
    context = ApplicationContext(application_type="web_app", purpose="demo")
    stamped = stamp_intentional_vulnerability(context, root, force=True)
    assert stamped.deliberately_vulnerable is True
    assert any("--include-intentional" in item for item in stamped.deliberate_vulnerability_evidence)


def test_local_only_suppression_is_disabled_for_targets():
    context = ApplicationContext(application_type="cli_tool", purpose="demo",
                                 requires_remote_trigger=False)
    assert context.suppress_local_only() is True
    context.deliberately_vulnerable = True
    assert context.suppress_local_only() is False


def test_stage1_prompt_reports_instead_of_suppressing():
    from prompts.vulnerability_analysis import get_analysis_prompt

    context = ApplicationContext(
        application_type="web_app", purpose="practice target",
        not_a_vulnerability=["SQL injection on /login is a teaching feature"],
        deliberately_vulnerable=True,
        deliberate_vulnerability_evidence=["README.md: 声明故意保留漏洞（deliberately vulnerable）"],
    )
    prompt = get_analysis_prompt("def f(): pass", "python", app_context=context)
    assert "STILL REPORT" in prompt
    assert "Do NOT flag as vulnerable" not in prompt
    assert "SQL injection on /login" not in prompt
    assert "README.md" in prompt


def test_stage2_prompt_judges_exploitability_not_intent():
    from prompts.verification_prompts import get_verification_prompt

    context = ApplicationContext(
        application_type="web_app", purpose="practice target",
        not_a_vulnerability=["XSS on /guestbook is a teaching feature"],
        deliberately_vulnerable=True,
        deliberate_vulnerability_evidence=["README.md: 声明故意保留漏洞"],
    )
    finding = {"name": "XSS", "cwe_id": 79, "description": "x",
               "vulnerable_code": "x", "attack_vector": "x", "impact": "x", "steps_to_reproduce": "x"}
    prompt = get_verification_prompt("print(1)", "python", finding, "stage-1 reasoning",
                                      app_context=context)
    assert "judge exploitability, not intent" in prompt
    assert "XSS on /guestbook is a teaching feature" not in prompt
