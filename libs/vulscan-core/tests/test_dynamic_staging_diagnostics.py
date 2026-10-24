# Modified 2026-10-23 for the VulScan-only product namespace.
"""Controlled staging and mocked Docker boundaries; no actual container execution."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import utilities.dynamic_tester as dt
from utilities.dynamic_tester import docker_executor as executor
from utilities.dynamic_tester import test_generator as generator
from utilities.dynamic_tester.result_collector import collect_result
from utilities.llm_client import TokenTracker


@pytest.mark.parametrize("source_name,test_name,req_name", [
    ("test_exploit.js", "test_exploit.js", "package.json"),
    ("test_exploit.py", "test_exploit.py", "requirements.txt"),
    ("test_exploit.go", "test_exploit.go", "go.mod"),
    ("package.json", "test_exploit.js", "package.json"),
    ("Dockerfile", "test_exploit.js", "package.json"),
    ("target.js", "package.json", "package.json"),
])
def test_staging_rejects_collisions_before_overwriting(tmp_path, source_name, test_name, req_name):
    source = tmp_path / source_name
    source.write_text("original target", encoding="utf-8")
    staging = tmp_path / "staged"
    staging.mkdir()
    generation = {"dockerfile": "FROM example", "test_script": "harness",
                  "test_filename": test_name, "requirements": "manifest",
                  "requirements_filename": req_name}
    with pytest.raises(ValueError, match="冲突|同名"):
        executor._write_test_files(str(staging), generation, str(source))
    assert not list(staging.iterdir())
    assert source.read_text(encoding="utf-8") == "original target"


@pytest.mark.parametrize("as_bytes", [False, True])
def test_command_timeout_keeps_partial_diagnostics(monkeypatch, as_bytes):
    import sys
    monkeypatch.delenv("VULSCAN_DOCKER_OWNER", raising=False)
    # Real pipes exercise decoding and partial-output retention, not an obsolete
    # subprocess.run mock that bypasses bounded streaming.
    script = ("import os,time; "
              "os.write(1, b'dependency resolve started'); "
              "os.write(2, b'compiler diagnostic at end'); time.sleep(10)") if as_bytes else (
              "import sys,time; print('dependency resolve started', flush=True); "
              "print('compiler diagnostic at end', file=sys.stderr, flush=True); time.sleep(10)")
    out, err, code, timed_out = executor._run_command([sys.executable, "-c", script], 1)
    assert "dependency resolve started" in out
    assert "compiler diagnostic at end" in err and "超时" in err
    assert code == -1 and timed_out


@pytest.mark.parametrize("compose", [False, True])
@pytest.mark.parametrize("timed_out", [False, True])
def test_build_failure_keeps_both_streams(monkeypatch, compose, timed_out):
    monkeypatch.setattr(executor, "_run_command", lambda *args, **kwargs:
        ("stdout dependency error", "stderr build summary", -1 if timed_out else 1, timed_out))
    run = executor._run_compose if compose else executor._run_single
    args = (".", "fixture", 1, 1) if compose else (".", "fixture", "network", 1, 1)
    result = run(*args)
    assert "stdout dependency error" in result.build_error
    assert "stderr build summary" in result.build_error
    assert result.timed_out == timed_out


def test_runtime_timeout_keeps_evidence_without_changing_verdict():
    execution = executor.DockerExecutionResult()
    execution.timed_out = True
    execution.stdout = "last harness step"
    execution.stderr = "last runtime diagnostic"
    result = collect_result({"id": "F"}, {"test_script": "fixture"}, execution)
    assert result.status == "INCONCLUSIVE"
    assert "last harness step" in result.evidence[0].content
    assert "last runtime diagnostic" in result.evidence[0].content


@pytest.mark.parametrize("language,filename,test_filename,requirements_filename", [
    ("javascript", "target.js", "test_exploit.js", "package.json"),
    ("python", "target.py", "test_exploit.py", "requirements.txt"),
    ("go", "target.go", "test_exploit.go", "go.mod"),
])
def test_imported_finding_reaches_staging_and_repairs_build_failure(
        tmp_path, monkeypatch, language, filename, test_filename, requirements_filename):
    """Public import + actual generation/repair/staging/collector, mocked LLM/Docker."""
    source = tmp_path / filename
    source.write_text("controlled target bytes", encoding="utf-8")
    pipeline = tmp_path / "pipeline.json"
    pipeline.write_text(json.dumps({"repository": {"name": "fixture", "language": "c"},
        "findings": [{"id": "F", "identity_key": "fixture", "stage2_verdict": "confirmed",
                      "location": {"file": filename, "line": 1}}]}), encoding="utf-8")
    prompts = []
    def complete(binding, prompt, **kwargs):
        prompts.append(prompt)
        return json.dumps({"dockerfile": "FROM fixture\n# " + str(len(prompts)),
            "test_script": "controlled harness", "test_filename": test_filename,
            "requirements": "", "requirements_filename": requirements_filename,
            "docker_compose": None, "needs_attacker_server": False})
    builds = []
    def command(cmd, timeout, cwd=None):
        if cmd[:2] == ["docker", "info"]:
            return "fixture-daemon", "", 0, False
        if cmd[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "0B"}), "", 0, False
        if cmd[:2] == ["docker", "build"]:
            assert (Path(cwd) / "repository" / filename).read_text(encoding="utf-8") == "controlled target bytes"
            assert (Path(cwd) / test_filename).read_text(encoding="utf-8") == "controlled harness"
            builds.append(cwd)
            if len(builds) == 1:
                return "precise dependency/compiler diagnostic", "build failed", 1, False
        if cmd[:2] == ["docker", "run"]:
            return json.dumps({"status": "NOT_REPRODUCED", "details": "受控测试完成", "evidence": []}), "", 0, False
        return "", "", 0, False
    monkeypatch.setattr(generator, "simple_text", complete)
    monkeypatch.setattr(executor, "_run_command", command)
    monkeypatch.setattr(dt, "get_global_tracker", lambda: TokenTracker())
    results = dt.run_dynamic_tests(str(pipeline), str(tmp_path / "out"), repo_path=str(tmp_path),
        registry=SimpleNamespace(get=lambda phase: object()))
    assert len(builds) == 2 and len(prompts) == 2
    assert f"Language: {language}" in prompts[0]
    assert "precise dependency/compiler diagnostic" in prompts[1]
    assert results[0].status == "NOT_REPRODUCED" and results[0].retry_count == 1
