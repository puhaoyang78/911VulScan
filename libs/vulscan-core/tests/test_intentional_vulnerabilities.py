"""靶场/教学仓库：自动识别、上下文标记与两个阶段提示词的行为。"""

from pathlib import Path

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
