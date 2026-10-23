"""Resource lifecycle regressions using controlled processes and fake Docker only."""
import json
from pathlib import Path
import sys

import pytest
import yaml

from utilities import docker_resources as resources
from utilities.dynamic_tester import docker_executor as executor

GEN = {"dockerfile": "FROM fixture", "test_script": "print('fixture')"}


def fake_docker(calls, failure=None):
    def run(cmd, timeout, cwd=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "info"]:
            return "fixture-daemon-id", "", 0, False
        if cmd[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "0B"}), "", 0, False
        if cmd[:2] == ["docker", "build"] and failure:
            if isinstance(failure, BaseException):
                raise failure
            return "partial", "failed", -1, True
        return "", "", 0, False
    return run


@pytest.mark.parametrize("failure", [None, "timeout", KeyboardInterrupt()])
def test_success_timeout_interruption_always_cleanup(tmp_path, monkeypatch, failure):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    calls = []
    monkeypatch.setattr(executor, "_run_command", fake_docker(calls, failure))
    if isinstance(failure, BaseException):
        with pytest.raises(KeyboardInterrupt):
            executor.run_single_container(GEN, "F")
    else:
        result = executor.run_single_container(GEN, "F")
        assert result.reproduction["cleanup"]["ok"]
        assert result.timed_out == bool(failure)
    assert not list(registry.iterdir())
    assert any(cmd[:2] == ["docker", "ps"] for cmd in calls)
    builds = [cmd for cmd in calls if cmd[:2] == ["docker", "build"]]
    assert resources.OWNER_LABEL in " ".join(builds[0])
    runtime = [cmd for cmd in calls if cmd[:2] == ["docker", "run"]]
    if runtime:
        assert "--name" in runtime[0] and "--log-driver" in runtime[0]


def test_cleanup_failure_visible_and_recovery_retained(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    calls = []
    base = fake_docker(calls)
    def command(cmd, **kwargs):
        if cmd[:2] == ["docker", "ps"]:
            return "", "daemon offline", 1, False
        return base(cmd, **kwargs)
    monkeypatch.setattr(executor, "_run_command", command)
    result = executor.run_single_container(GEN, "F")
    assert result.infrastructure_error and result.execution_error
    assert not result.reproduction["cleanup"]["ok"]
    manifests = list(registry.glob("*.json"))
    assert len(manifests) == 1
    entry = json.loads(manifests[0].read_text())
    assert Path(entry["work_dir"]).is_dir()
    assert resources.cleanup_owner(entry["owner"], runner=fake_docker([])) == []
    assert not Path(entry["work_dir"]).exists()


def test_compose_custom_tag_replaced_external_image_preserved(tmp_path):
    path = tmp_path / "docker-compose.yml"
    path.write_text(executor._sanitize_compose("""services:
  test:
    image: shared/user:latest
    build: .
  database:
    image: shared/database:latest
"""))
    run_id = "a" * 32
    executor._label_compose(str(tmp_path), run_id)
    data = yaml.safe_load(path.read_text())
    assert data["services"]["test"]["image"] == f"openant-{run_id}-0:latest"
    assert data["services"]["database"]["image"] == "shared/database:latest"
    assert data["services"]["test"]["build"]["labels"][resources.RUN_LABEL] == run_id
    assert data["networks"]["default"]["labels"][resources.RUN_LABEL] == run_id


@pytest.mark.parametrize("stage", ["build", "up", "logs"])
def test_compose_interrupt_each_stage_tears_down(monkeypatch, stage):
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        if stage in cmd:
            raise KeyboardInterrupt()
        return "", "", 0, False
    monkeypatch.setattr(executor, "_run_command", run)
    with pytest.raises(KeyboardInterrupt):
        executor._run_compose("/tmp/fixture", "project", 1, 1)
    assert "down" in calls[-1]
    assert "--rmi" not in calls[-1]


def test_compose_start_failure_not_observed(monkeypatch):
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        return ("", "start failed", 1, False) if "up" in cmd else ("", "", 0, False)
    monkeypatch.setattr(executor, "_run_command", run)
    result = executor._run_compose("/tmp/fixture", "project", 1, 1)
    assert result.execution_error and not any("logs" in cmd for cmd in calls)
    assert "down" in calls[-1]


def test_command_output_bounded_both_streams():
    code = "import os; os.write(1,b'x'*2000000+b'ENDOUT'); os.write(2,b'y'*2000000+b'ENDERR')"
    out, err, status, timed = executor._run_command([sys.executable, "-c", code], 10)
    assert status == 0 and not timed
    assert len(out) < executor.MAX_COMMAND_OUTPUT + 100
    assert len(err) < executor.MAX_COMMAND_OUTPUT + 100
    assert out.endswith("ENDOUT") and err.endswith("ENDERR")
    assert "truncated" in out and "truncated" in err


@pytest.mark.parametrize("context", ["https://host/repo", "git@host:repo", "${HOME}", "C:\\tmp", "\\tmp", "../x"])
def test_remote_or_expanded_build_context_refused(context):
    with pytest.raises(ValueError):
        executor._safe_build(context)


@pytest.mark.parametrize("managed", [False, True])
def test_timeout_stops_cli_and_descendant_producer(tmp_path, monkeypatch, managed):
    import psutil
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    if managed:
        monkeypatch.setenv("OPENANT_DOCKER_OWNER", "b" * 32)
    else:
        monkeypatch.delenv("OPENANT_DOCKER_OWNER", raising=False)
    marker = tmp_path / "late-write"
    child_code = f"import time; time.sleep(2); open({str(marker)!r},'w').write('leaked'); time.sleep(30)"
    code = ("import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c'," +
            repr(child_code) + "]); print(p.pid,flush=True); time.sleep(30)")
    out, err, status, timed = executor._run_command([sys.executable, "-c", code], 0.3)
    assert timed and status == -1
    pid = int(out.strip())
    assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    assert not marker.exists()
    assert not list(registry.glob("*.producer.json"))


def test_compose_service_budget_fails_closed():
    content = yaml.safe_dump({"services": {f"svc{i}": {"image": "fixture"} for i in range(9)}})
    assert "eight-service resource budget" in executor._sanitize_compose(content)


def test_custom_builder_controls_not_inherited(monkeypatch):
    monkeypatch.setenv("BUILDKIT_HOST", "tcp://unmeasured:1234")
    monkeypatch.setenv("BUILDX_BUILDER", "unmeasured")
    monkeypatch.setenv("COMPOSE_DOCKER_CLI_BUILD", "1")
    monkeypatch.setenv("COMPOSE_FILE", "/untrusted/override.yml")
    monkeypatch.setenv("DOCKER_BUILDKIT", "0")
    env = executor._scrubbed_subprocess_env()
    assert env["DOCKER_BUILDKIT"] == "1"
    assert not {"BUILDKIT_HOST", "BUILDX_BUILDER", "COMPOSE_DOCKER_CLI_BUILD", "COMPOSE_FILE"} & env.keys()


def test_unsupported_builder_flag_is_infrastructure_error(monkeypatch):
    monkeypatch.setattr(executor, "_run_command", lambda *args, **kwargs:
                        ("", "unknown flag: --builder", 1, False))
    result = executor._run_single(".", "fixture", "network", 1, 1)
    assert result.infrastructure_error and result.build_error


def test_repeated_finding_uses_disjoint_resources(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    calls = []
    monkeypatch.setattr(executor, "_run_command", fake_docker(calls))
    for _ in range(2):
        assert executor.run_single_container(GEN, "same-finding").success
    builds = [cmd for cmd in calls if cmd[:2] == ["docker", "build"]]
    tags = [cmd[cmd.index("-t") + 1] for cmd in builds]
    assert len(set(tags)) == 2
    assert not list(registry.iterdir())


def test_admission_failure_preserves_artifacts(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    calls = []
    base = fake_docker(calls)
    def command(cmd, **kwargs):
        if cmd[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "999GB"}), "", 0, False
        return base(cmd, **kwargs)
    monkeypatch.setattr(executor, "_run_command", command)
    result = executor.run_single_container(GEN, "fixture")
    assert result.infrastructure_error and result.execution_error
    assert result.reproduction["artifacts"]
    assert not any(cmd[:2] == ["docker", "build"] for cmd in calls)


def test_generated_staging_collision_remains_repairable(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    source = tmp_path / "target.py"
    source.write_text("# actual target\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(executor, "_run_command", fake_docker(calls))
    result = executor.run_single_container(
        {**GEN, "test_filename": "target.py"}, "staging-collision", source_file=str(source))
    assert result.execution_error and "冲突" in result.execution_error
    assert not result.infrastructure_error
    assert result.reproduction["cleanup"]["ok"]
    assert not calls  # Prepared-only cleanup requires neither Docker nor a build.
    assert source.read_text(encoding="utf-8") == "# actual target\n"
    assert not list(registry.iterdir())
