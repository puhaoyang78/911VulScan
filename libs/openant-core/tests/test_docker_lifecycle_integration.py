"""Opt-in real-daemon smoke tests; no LLM, target repository or global pruning.

Run only on an explicitly provisioned disposable CI Docker daemon:
    OPENANT_DOCKER_LIFECYCLE_TESTS=1 pytest tests/test_docker_lifecycle_integration.py
The official busybox:1.37 image may be downloaded; its shared base cache is retained.
"""
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

import pytest

from utilities import docker_resources as resources
from utilities.dynamic_tester import docker_executor as executor

pytestmark = pytest.mark.skipif(
    os.environ.get("OPENANT_DOCKER_LIFECYCLE_TESTS") != "1",
    reason="requires explicit isolated real-Docker lifecycle opt-in",
)

BASE = "busybox:1.37"


def command(argv, timeout=60):
    out, err, code, timed = executor._run_command(argv, timeout)
    assert code == 0 and not timed, f"{argv!r}: {out}\n{err}"
    return out.strip()


def owned_inventory(owner):
    label = ["--filter", f"label={resources.OWNER_LABEL}={owner}"]
    return {
        "containers": command(["docker", "ps", "-aq", *label]).split(),
        "networks": command(["docker", "network", "ls", "-q", *label]).split(),
        "images": command(["docker", "image", "ls", "-q", *label]).split(),
    }


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    assert shutil.which("docker"), "opt-in real-Docker validation requires Docker CLI"
    owner = uuid.uuid4().hex
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_OWNER", owner)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(registry))
    monkeypatch.delenv("OPENANT_DOCKER_LEASE_FD", raising=False)
    command(["docker", "info", "--format", "{{.ID}}"])
    command(["docker", "buildx", "version"])
    command(["docker", "compose", "version"])
    assert all(not ids for ids in owned_inventory(owner).values())
    # Keep an independent, daemon-pinned recovery manifest until fixture teardown.
    # If the code under test incorrectly forgets its manifest, the fixture can still
    # remove only this unguessable owner's resources rather than leaking CI fixtures.
    recovery_run = uuid.uuid4().hex
    staging = tempfile.mkdtemp(prefix="openant-test-integration-recovery-")
    resources.register_run(recovery_run, staging)
    resources.bind_run_daemon(recovery_run, runner=executor._run_command)
    try:
        yield owner
    finally:
        errors = resources.cleanup_owner(owner, runner=executor._run_command)
        assert not errors, errors
        assert all(not ids for ids in owned_inventory(owner).values())
        assert not Path(staging).exists()


def generation(command_json):
    return {"dockerfile": f"FROM {BASE}\nCMD {json.dumps(command_json)}\n",
            "test_script": "# controlled fixture; not executed by this image\n",
            "test_filename": "fixture.py"}


@pytest.mark.parametrize("outcome", ["success", "timeout", "build_failure"])
def test_single_real_lifecycle(daemon, outcome):
    spec = generation(["sh", "-c", "echo controlled-success"])
    if outcome == "timeout":
        spec = generation(["sh", "-c", "echo controlled-start; sleep 60"])
    elif outcome == "build_failure":
        spec["dockerfile"] = f"FROM {BASE}\nRUN false\n"
    result = executor.run_single_container(spec, "real-lifecycle", container_timeout=3,
                                           build_timeout=120)
    assert result.reproduction["cleanup"]["ok"], result.reproduction
    if outcome == "success":
        assert result.success, result.__dict__
        assert "controlled-success" in result.stdout
    elif outcome == "timeout":
        assert result.timed_out and not result.success, result.__dict__
        assert "controlled-start" in result.stdout
    else:
        assert result.build_error and not result.success, result.__dict__
    assert all(not ids for ids in owned_inventory(daemon).values())


def test_compose_custom_build_tag_and_shared_image_preserved(daemon):
    # Pull only an official tiny fixture image; its shared tag must survive teardown.
    command(["docker", "pull", BASE], timeout=120)
    shared_id = command(["docker", "image", "inspect", "--format", "{{.Id}}", BASE])
    custom_tag = "openant-integration-untrusted-" + uuid.uuid4().hex + ":latest"
    spec = generation(["sh", "-c", "echo controlled-compose"])
    spec.update({"needs_attacker_server": True, "docker_compose": f"""services:
  test:
    build: .
    image: {custom_tag}
  fixture:
    image: {BASE}
    command: ["sh", "-c", "sleep 60"]
"""})
    # The tag is minted only for this fixture and verified absent before execution.
    _, _, initial_code, _ = executor._run_command(["docker", "image", "inspect", custom_tag], 30)
    assert initial_code != 0
    try:
        result = executor.run_single_container(spec, "real-compose", container_timeout=2,
                                               build_timeout=120)
        assert not result.build_error and not result.execution_error, result.__dict__
        assert "controlled-compose" in result.stdout, result.__dict__
        assert result.reproduction["cleanup"]["ok"]
        # A generated build+image field is overridden, not created then force-deleted.
        _, _, code, _ = executor._run_command(["docker", "image", "inspect", custom_tag], 30)
        assert code != 0
        assert command(["docker", "image", "inspect", "--format", "{{.Id}}", BASE]) == shared_id
        assert all(not ids for ids in owned_inventory(daemon).values())
    finally:
        # Remove only the fixture's fresh exact tag if a regression created it;
        # never remove a shared image ID or use force/global pruning.
        executor._run_command(["docker", "image", "rm", custom_tag], 30)


@pytest.mark.skipif(os.name != "posix", reason="SIGKILL recovery smoke test requires Unix")
def test_parent_sigkill_recovers_live_daemon_container(daemon):
    import subprocess
    import sys
    import time

    spec = generation(["sh", "-c", "echo controlled-orphan; sleep 120"])
    script = ("from utilities.dynamic_tester.docker_executor import run_single_container; "
              f"run_single_container({spec!r}, 'real-orphan', container_timeout=120, build_timeout=120)")
    core = str(Path(__file__).resolve().parents[1])
    child = subprocess.Popen([sys.executable, "-c", script], cwd=core,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            assert child.poll() is None, "controlled Python producer exited before its container started"
            running = command(["docker", "ps", "-q", "--filter",
                               f"label={resources.OWNER_LABEL}={daemon}"])
            if running:
                break
            time.sleep(0.2)
        else:
            pytest.fail("controlled container did not start within its build/runtime budget")
        # Kill only our spawned scanner, deliberately leaving Docker CLI and
        # daemon container alive for the ownership registry's recovery path.
        child.kill()
        child.wait(timeout=10)
        recovered = subprocess.run(
            [sys.executable, "-m", "utilities.docker_resources", "cleanup", "--owner", daemon],
            cwd=core, capture_output=True, text=True, timeout=120)
        assert recovered.returncode == 0, recovered.stdout + recovered.stderr
        assert all(not ids for ids in owned_inventory(daemon).values())
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
