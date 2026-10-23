"""Owned cleanup never prunes or crosses scan boundaries; admission is fail-closed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest
from utilities import docker_resources as resources

OWNER = "a" * 32
RUN = "b" * 32


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "registry"
    path.mkdir(mode=0o700)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(path))
    monkeypatch.setenv("OPENANT_DOCKER_OWNER", OWNER)
    return path


def empty_daemon(cmd, **kwargs):
    return ("fixture-daemon" if cmd[1:2] == ["info"] else "", "", 0, False)


@pytest.fixture
def registered(registry):
    work = tempfile.mkdtemp(prefix="openant-test-registry-")
    resources.register_run(RUN, work)
    resources.bind_run_daemon(RUN, runner=empty_daemon)
    yield registry
    shutil.rmtree(work, ignore_errors=True)


def test_registry_cleanup_retries_failure_and_preserves_other_owner(registry):
    work = tempfile.mkdtemp(prefix="openant-test-registry-")
    try:
        resources.register_run(RUN, work)
        resources.bind_run_daemon(RUN, runner=empty_daemon)
        foreign = registry / (("c" * 32) + "-" + RUN + ".json")
        foreign.write_text("not ours")
        errors = resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: ("", "offline", 1, False))
        assert errors and Path(work).exists()
        assert len(list(registry.glob("*.json"))) == 2
        assert resources.cleanup_owner(OWNER, RUN, runner=empty_daemon) == []
        assert not Path(work).exists()
        assert foreign.read_text() == "not ours"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_cleanup_only_labels_and_owned_tags(registered):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1:2] == ["info"]:
            return "fixture-daemon", "", 0, False
        if cmd[1:3] == ["ps", "-aq"] or cmd[1:4] == ["network", "ls", "-q"]:
            return "d" * 64, "", 0, False
        if cmd[1:4] == ["image", "ls", "-q"]:
            return "e" * 64, "", 0, False
        if cmd[1:3] in (["container", "inspect"], ["network", "inspect"]):
            labels = {resources.OWNER_LABEL: OWNER, resources.RUN_LABEL: RUN}
            return json.dumps([{"Config": {"Labels": labels}, "Labels": labels}]), "", 0, False
        if cmd[1:3] == ["image", "inspect"]:
            return json.dumps([{"Config": {"Labels": {resources.OWNER_LABEL: OWNER,
                                                        resources.RUN_LABEL: RUN}},
                                "RepoTags": [f"openant-{RUN}-test:latest", "shared:latest"]}]), "", 0, False
        return "", "", 0, False
    assert resources.cleanup_owner(OWNER, RUN, runner) == []
    for cmd in calls:
        if "ls" in cmd or "ps" in cmd:
            assert f"label={resources.OWNER_LABEL}={OWNER}" in cmd
            assert f"label={resources.RUN_LABEL}={RUN}" in cmd
    assert ["docker", "image", "rm", f"openant-{RUN}-test:latest"] in calls
    assert not any("shared:latest" in cmd or "prune" in cmd for cmd in calls)
    assert not any(cmd[:3] == ["docker", "image", "rm"] and "e" * 64 in cmd for cmd in calls)


def test_image_inspection_checks_owner_again(registered):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1:2] == ["info"]:
            return "fixture-daemon", "", 0, False
        if cmd[1:4] == ["image", "ls", "-q"]:
            return "e" * 64, "", 0, False
        if cmd[1:3] == ["image", "inspect"]:
            return json.dumps([{"Config": {"Labels": {resources.OWNER_LABEL: "c" * 32,
                                                        resources.RUN_LABEL: RUN}}}]), "", 0, False
        return "", "", 0, False
    assert resources.cleanup_owner(OWNER, RUN, runner)
    assert not any(cmd[:3] == ["docker", "image", "rm"] for cmd in calls)


def test_shared_cache_budget_refuses(registry, monkeypatch):
    monkeypatch.setenv("OPENANT_DOCKER_CACHE_MAX_BYTES", "1000")
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**12, 0, 10**12))
    runner = lambda *a, **k: ('{"Type":"Build Cache","Size":"2kB"}', "", 0, False)
    with pytest.raises(RuntimeError, match="admission budget"):
        with resources.build_admission(runner=runner):
            pytest.fail("must not admit")


def test_unknown_cache_refuses(registry, monkeypatch):
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**12, 0, 10**12))
    with pytest.raises(RuntimeError, match="parse Docker cache"):
        with resources.build_admission(runner=lambda *a, **k: ("", "", 0, False)):
            pytest.fail("must not admit")


def test_build_disk_pressure_refuses(registry, monkeypatch):
    monkeypatch.setenv("OPENANT_ALLOW_SHARED_BUILD_CACHE", "1")
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10, 9, 1))
    with pytest.raises(RuntimeError, match="less than 2 GiB"):
        with resources.build_admission():
            pytest.fail("must not admit")


def test_build_lock_serializes_and_releases(registry, monkeypatch):
    pytest.importorskip("fcntl")
    monkeypatch.setenv("OPENANT_ALLOW_SHARED_BUILD_CACHE", "1")
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**12, 0, 10**12))
    with resources.build_admission(runner=lambda *a, **k: ('{"Type":"Build Cache","Size":"0B"}', "", 0, False)):
        with pytest.raises(TimeoutError, match="admission"):
            with resources.build_admission(timeout=0.01):
                pytest.fail("second build acquired active lock")
    with resources.build_admission(timeout=0.01, runner=lambda *a, **k: ('{"Type":"Build Cache","Size":"0B"}', "", 0, False)):
        pass


def test_registry_rejects_symlink_and_changed_staging_identity(registry):
    work = tempfile.mkdtemp(prefix="openant-test-registry-")
    try:
        resources.register_run(RUN, work)
        entry_path = next(registry.glob("*.json"))
        entry = json.loads(entry_path.read_text())
        entry["inode"] += 1
        entry_path.write_text(json.dumps(entry))
        assert resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: ("", "", 0, False))
        assert Path(work).exists() and entry_path.exists()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_cleanup_runner_bounded_and_timeout():
    out, err, code, timed = resources._cleanup_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x'*2000000)"], 5)
    assert len(out) == 1024 * 1024 and code == 125 and not timed
    out, err, code, timed = resources._cleanup_command(
        [sys.executable, "-c", "import time; time.sleep(20)"], 0.01)
    assert timed and code != 0


def test_owner_token_injection_rejected(registry):
    with pytest.raises(ValueError):
        resources.cleanup_owner("--all", runner=lambda *a, **k: pytest.fail("docker called"))


def test_build_lock_released_after_process_kill(registry, monkeypatch):
    pytest.importorskip("fcntl")
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(10**12, 0, 10**12))
    code = '''
import time
from utilities import docker_resources as r
r.shutil.disk_usage = lambda p: type('Disk', (), {'free': 10**12})()
with r.build_admission(runner=lambda *a, **k: ('{"Type":"Build Cache","Size":"0B"}', '', 0, False)):
    print('locked', flush=True)
    time.sleep(60)
'''
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        with pytest.raises(TimeoutError):
            with resources.build_admission(timeout=0.01):
                pytest.fail("concurrent process bypassed build lock")
        proc.kill()
        proc.wait(timeout=5)
        with resources.build_admission(timeout=0.1, runner=lambda *a, **k: ('{"Type":"Build Cache","Size":"0B"}', "", 0, False)):
            pass
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        proc.stdout.close()


def test_cli_import_has_no_llm_dependencies(registry):
    completed = subprocess.run([sys.executable, "-P", "-m", "utilities.docker_resources",
                                "cleanup", "--owner", "invalid"],
                               capture_output=True, text=True, timeout=5)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["ok"] is False
    assert "32-character" in completed.stdout
    assert not completed.stderr


def test_producer_cleanup_kills_registered_process(registry):
    pytest.importorskip("psutil")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        resources.register_producer(proc.pid)
        assert list(registry.glob("*.producer.json"))
        assert resources.cleanup_owner(OWNER, runner=lambda *a, **k: ("", "", 0, False)) == []
        proc.wait(timeout=5)
        assert not list(registry.glob("*.producer.json"))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_producer_recycled_pid_not_signalled(registry):
    pytest.importorskip("psutil")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        resources.register_producer(proc.pid)
        path = next(registry.glob("*.producer.json"))
        entry = json.loads(path.read_text())
        entry["created"] -= 100
        path.write_text(json.dumps(entry))
        assert resources.cleanup_owner(OWNER, runner=lambda *a, **k: ("", "", 0, False)) == []
        assert proc.poll() is None
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_partial_producer_traversal_does_not_leave_suspended_process(registry, monkeypatch):
    psutil = pytest.importorskip("psutil")
    path = registry / f"{OWNER}-12345.producer.json"
    path.write_text(json.dumps({"owner": OWNER, "pid": 12345, "created": 10}))
    class Process:
        pid = 12345
        killed = False
        def create_time(self): return 10
        def suspend(self): pass
        def children(self): raise psutil.AccessDenied(self.pid)
        def kill(self): self.killed = True
    process = Process()
    monkeypatch.setattr(psutil, "Process", lambda pid: process)
    errors = resources.cleanup_owner(OWNER, runner=lambda *a, **k: pytest.fail("Docker deletion before producer termination"))
    assert errors and process.killed and path.exists()
    assert json.loads(path.read_text())["uncertain_descendants"] is True


def test_registry_root_symlink_rejected(tmp_path, monkeypatch):
    target = tmp_path / "actual"
    target.mkdir(mode=0o700)
    link = tmp_path / "registry-link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(link))
    with pytest.raises(RuntimeError, match="private owned"):
        resources._state_dir()


def test_manifest_symlink_does_not_authorize_deletion(registry, tmp_path):
    target = tmp_path / "foreign.json"
    target.write_text("{}")
    link = registry / f"{OWNER}-{RUN}.json"
    link.symlink_to(target)
    assert resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: ("", "", 0, False))
    assert target.read_text() == "{}" and link.is_symlink()


def test_windows_byte_lock_abstraction(tmp_path, monkeypatch):
    import types
    calls = []
    fake = types.SimpleNamespace(LK_NBLCK=1, locking=lambda fd, mode, size: calls.append((mode, size)))
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    monkeypatch.setattr(resources.sys, "platform", "win32")
    fd = os.open(tmp_path / "lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        assert resources._try_build_lock(fd)
        assert os.fstat(fd).st_size == 1 and calls == [(1, 1)]
        def busy(*args): raise OSError(13, "locked")
        fake.locking = busy
        assert resources._try_build_lock(fd) is False
    finally:
        os.close(fd)


def test_uncertain_departed_producer_blocks_resource_cleanup(registry):
    pytest.importorskip("psutil")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    resources.register_producer(proc.pid)
    resources.mark_producer_uncertain(proc.pid)
    proc.kill()
    proc.wait(timeout=5)
    errors = resources.cleanup_owner(OWNER, runner=lambda *a, **k: pytest.fail("must retain Docker resources"))
    assert errors and "untracked descendants" in errors[0]
    assert list(registry.glob("*.producer.json"))


def test_worker_run_lease_blocks_reaper_and_releases(registry, monkeypatch):
    fcntl = pytest.importorskip("fcntl")
    monkeypatch.setenv("OPENANT_DOCKER_LEASE_FD", "999")
    lease = registry / ".lease"
    lease.touch(mode=0o600)
    work = tempfile.mkdtemp(prefix="openant-test-lease-")
    fd = os.open(lease, os.O_RDWR)
    try:
        resources.register_run(RUN, work)
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: ("", "", 0, False)) == []
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)
        resources._release_run_lease(RUN)
        shutil.rmtree(work, ignore_errors=True)


def test_recovered_managed_registry_not_recreated(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(tmp_path / "gone"))
    monkeypatch.setenv("OPENANT_DOCKER_LEASE_FD", "999")
    with pytest.raises(RuntimeError, match="disappeared"):
        resources._state_dir()
    assert not (tmp_path / "gone").exists()


@pytest.mark.parametrize("kind", ["container", "network"])
def test_runtime_resource_inspect_rechecks_owner(registered, kind):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1:2] == ["info"]:
            return "fixture-daemon", "", 0, False
        listing = ["ps", "-aq"] if kind == "container" else ["network", "ls", "-q"]
        if cmd[1:1+len(listing)] == listing:
            return "f" * 64, "", 0, False
        if cmd[1:3] == [kind, "inspect"]:
            labels = {resources.OWNER_LABEL: "c" * 32, resources.RUN_LABEL: RUN}
            return json.dumps([{"Config": {"Labels": labels}, "Labels": labels}]), "", 0, False
        return "", "", 0, False
    assert resources.cleanup_owner(OWNER, RUN, runner)
    assert not any("rm" in cmd for cmd in calls)


def test_changed_daemon_retains_recovery_and_never_removes_resources(registered):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return "different-daemon", "", 0, False
    errors = resources.cleanup_owner(OWNER, RUN, runner)
    assert errors and "identity changed" in errors[0]
    assert len(calls) == 1 and calls[0][1] == "info"
    assert list(registered.glob("*.json"))


def test_prepared_only_cleanup_never_calls_docker(registry):
    work = tempfile.mkdtemp(prefix="openant-test-prepared-")
    resources.register_run(RUN, work)
    try:
        assert resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: pytest.fail("no resources created")) == []
        assert not Path(work).exists()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_daemon_identity_unavailable_prevents_binding(registry):
    work = tempfile.mkdtemp(prefix="openant-test-bind-")
    try:
        resources.register_run(RUN, work)
        with pytest.raises(RuntimeError, match="daemon identity"):
            resources.bind_run_daemon(RUN, runner=lambda *a, **k: ("", "offline", 1, False))
        entry = json.loads(next(registry.glob("*.json")).read_text())
        assert "daemon_id" not in entry
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_changed_staging_to_symlink_retains_target_and_evidence(registry, tmp_path):
    work = tempfile.mkdtemp(prefix="openant-test-link-")
    target = tmp_path / "unrelated"
    target.mkdir()
    (target / "keep").write_text("user data")
    resources.register_run(RUN, work)
    shutil.rmtree(work)
    Path(work).symlink_to(target, target_is_directory=True)
    try:
        assert resources.cleanup_owner(OWNER, RUN, runner=lambda *a, **k: pytest.fail("prepared only"))
        assert (target / "keep").read_text() == "user data"
        assert list(registry.glob("*.json"))
    finally:
        Path(work).unlink()
