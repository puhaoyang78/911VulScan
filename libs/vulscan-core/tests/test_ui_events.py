"""Deterministic UI telemetry; never invokes an adapter or Docker."""
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from core import ui_events
from core.progress import ProgressReporter
from report.details import model_review_status


def records(capsys):
    return [json.loads(s[len(ui_events.PREFIX):]) for s in capsys.readouterr().err.splitlines()
            if s.startswith(ui_events.PREFIX)]


def test_version_identity_and_thread_sequence(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda n: ui_events.emit("activity", message=str(n)), range(40)))
    events = records(capsys)
    assert [e["seq"] for e in events] == list(range(1, 42))
    assert all(e["job_id"] == "fixture" and e["version"] == 1 and e["time"] for e in events)


def test_review_and_dynamic_axes_are_independent(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    row = dict(route_key="src/a.c:copy", finding="vulnerable", cwe_id=120)
    ui_events.finding(row)
    row.update(verification={"agree": True}, exploit_path="model reasoning only", cwe_id=787)
    ui_events.finding(row, stage="verify")
    item = dict(id="VULN-001", location=dict(file="src/a.c", function="copy"))
    ui_events.dynamic(item, SimpleNamespace(status="NOT_REPRODUCED", details="no trigger", elapsed_seconds=1), attempt=2)
    events = records(capsys)
    found = [e for e in events if e["type"] == "finding.upsert"]
    assert found[0]["finding_id"] == found[1]["finding_id"] == "src/a.c:copy"
    assert found[1]["finding"]["model_review"] == "retained"
    assert "dynamic" not in found[1]["finding"]
    assert events[-1]["finding"]["dynamic"] == "not_reproduced"
    assert events[-1]["attempt"] == 2


def test_generation_build_environment_and_skip(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    item = dict(location=dict(file="a.py", function="handle"))
    result = SimpleNamespace(status="ERROR", details="dependency build failed", elapsed_seconds=2)
    execution = SimpleNamespace(infrastructure_error=True, build_error="no dependency")
    ui_events.dynamic(item, result, execution=execution)
    ui_events.dynamic(item, status="SKIPPED")
    events = records(capsys)
    assert events[0]["finding"]["dynamic"] == "environment_error"
    assert events[0]["finding"]["failure_phase"] == "build"
    assert events[1]["finding"]["dynamic"] == "skipped"


def test_progress_unique_units_does_not_change_scanner_retry_accounting(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=False, dynamic=False)
    progress = ProgressReporter("Detect", 3)
    progress.report("same-unit")
    progress.report("same-unit")
    assert progress.completed == 2  # original algorithm left intact
    events = [e for e in records(capsys) if e["type"] == "progress.updated"]
    assert [e["processed"] for e in events] == [0, 1, 1]
    assert all(e["total"] == 3 and e["stage"] == "analyze" for e in events)


def test_disabled_outside_web_runner(monkeypatch, capsys):
    monkeypatch.delenv("VULSCAN_JOB_ID", raising=False)
    ui_events.start(verify=True, dynamic=True)
    ui_events.emit("error", message="not emitted")
    assert records(capsys) == []


def test_build_activity_tolerates_blank_pipe_chunks_without_hiding_raw_output(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    records(capsys)
    observe = ui_events.command_output("build")
    observe("\r\n  \n")
    observe("dependencies ready\n")
    output = capsys.readouterr().err
    events = [json.loads(line[len(ui_events.PREFIX):]) for line in output.splitlines()
              if line.startswith(ui_events.PREFIX)]
    assert len(events) == 1
    assert events[0]["message"] == "dependencies ready"
    assert "[dynamic-test] [build]   " in output


def test_actual_review_semantics():
    assert model_review_status(dict(finding="vulnerable", verification={"agree": False})) == "retained"
    assert model_review_status(dict(finding="safe", verification={"agree": False})) == "excluded"
    assert model_review_status(dict(finding="vulnerable", verification={"incomplete": True})) == "inconclusive"
    assert model_review_status(dict(finding="inconclusive", verification={"agree": False})) == "inconclusive"
    assert model_review_status(dict(finding="insufficient_context", verification={"agree": False})) == "inconclusive"
    assert model_review_status(dict(finding="probably fine", verification={"agree": False})) == "error"
    assert model_review_status(dict(finding="vulnerable", verification={"explanation": "Max iterations reached"})) == "inconclusive"
    assert model_review_status(dict(finding="error", error="analysis failed")) == "unreviewed"
    assert model_review_status(dict(finding="vulnerable", error="verification failed", verification={"incomplete": True})) == "error"
    assert model_review_status(dict(finding="vulnerable")) == "unreviewed"


def test_partial_failure_or_output_rebuild_cannot_erase_a_real_reproduction(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    row = dict(route_key="a.c:copy", finding="vulnerable")
    ui_events.finding(row)
    item = dict(id="VULN-001", name="copy", location=dict(file="a.c", function="copy"))
    ui_events.pipeline_findings([item])
    ui_events.dynamic(item, SimpleNamespace(status="CONFIRMED", details="proof", elapsed_seconds=1))
    ui_events.skipped("dynamic-test", "failed")
    ui_events.pipeline_findings([item])
    events = records(capsys)
    states = [e["finding"]["dynamic"] for e in events if e.get("finding", {}).get("dynamic")]
    assert states == ["pending", "reproduced"]
    assert "dynamic" not in events[-1]["finding"]
    assert next(e for e in events if e.get("status") == "reproduced")["finding"]["failure_phase"] == ""


def test_failed_dynamic_preparation_closes_only_queued_tests(monkeypatch, capsys):
    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    for name in ("excluded", "running"):
        ui_events.finding(dict(route_key=f"a.c:{name}", finding="vulnerable"))
    queued = dict(id="VULN-001", location=dict(file="a.c", function="queued"))
    running = dict(id="VULN-002", location=dict(file="a.c", function="running"))
    ui_events.pipeline_findings([queued, running])
    ui_events.dynamic(running, status="RUNNING", attempt=1)
    records(capsys)
    ui_events.skipped("dynamic-test", "failed")
    events = records(capsys)
    assert events[0]["status"] == "error"
    updates = [e for e in events if e["type"] == "validation.updated"]
    assert [e["finding_id"] for e in updates] == ["a.c:queued"]
    assert updates[0]["finding"]["dynamic"] == "skipped"
    assert "测试未执行" in updates[0]["details"]


def test_final_coverage_includes_optional_phase_failure(monkeypatch, capsys, tmp_path):
    from core.scanner import _write_scan_report
    from core.schemas import ScanResult

    monkeypatch.setenv("VULSCAN_JOB_ID", "fixture")
    ui_events.start(verify=True, dynamic=True)
    result = ScanResult(output_dir=str(tmp_path))
    result.skipped_step_reasons["dynamic-test"] = "failed"
    _write_scan_report(str(tmp_path), result, [], repo_path=str(tmp_path))
    events = records(capsys)
    assert next(e for e in events if e["type"] == "coverage.updated")["status"] == "incomplete"


def test_command_output_keeps_finding_identity_across_pipe_threads(monkeypatch, capsys):
    monkeypatch.setenv('VULSCAN_JOB_ID', 'fixture')
    ui_events.start(verify=True, dynamic=True)
    ui_events.dynamic({'location':{'file':'main.py','function':'handle'}}, status='RUNNING', attempt=2)
    observer = ui_events.command_output('build')
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(observer, '#8 下载依赖中\n').result()
        pool.submit(observer, '#8 安装完成\n').result()
    output = capsys.readouterr().err
    events = [json.loads(line[len(ui_events.PREFIX):]) for line in output.splitlines() if line.startswith(ui_events.PREFIX)]
    activity = [e for e in events if e['type']=='activity']
    assert len(activity)==1  # bounded sampling, both lines remain in raw output
    assert activity[0]['finding_id']=='main.py:handle' and activity[0]['attempt']==2
    assert activity[0]['phase']=='build'
    assert '[dynamic-test] [build] #8 下载依赖中' in output
    assert '[dynamic-test] [build] #8 安装完成' in output
