"""Upstream #732 witnesses adapted to the fork's ownership-scoped lifecycle.

The production orchestrator names and labels each container, then removes it
by inspected owner/run identity in its outer finally before removing image tags.
This preserves timeout/exception coverage without bypassing ownership checks or
restoring upstream's unconditional name-based deletion.
"""
from __future__ import annotations

import re
import json


import utilities.dynamic_tester.docker_executor as de


class _FakeDocker:
    """Records argv; the `docker run` call returns the scripted outcome."""

    def __init__(self, run_outcome):
        self.calls = []
        self.labels = {}
        self.image = None
        self._run_outcome = run_outcome  # (stdout, stderr, code, timed_out)

    def __call__(self, cmd, timeout=None, cwd=None):
        self.calls.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return "fixture-daemon", "", 0, False
        if cmd[:3] == ["docker", "system", "df"]:
            return json.dumps({"Type": "Build Cache", "Size": "0B"}), "", 0, False
        if cmd[:2] == ["docker", "build"]:
            self.labels = dict(cmd[i + 1].split("=", 1) for i, v in enumerate(cmd) if v == "--label")
            self.image = cmd[cmd.index("-t") + 1]
        if cmd[:2] == ["docker", "run"]:
            if isinstance(self._run_outcome, BaseException):
                raise self._run_outcome
            return self._run_outcome
        if cmd[:2] == ["docker", "ps"]:
            return "a" * 64, "", 0, False
        if cmd[:3] == ["docker", "image", "ls"]:
            return "b" * 64, "", 0, False
        if cmd[:3] in (["docker", "container", "inspect"], ["docker", "image", "inspect"]):
            return json.dumps([{"Config": {"Labels": self.labels}, "RepoTags": [self.image]}]), "", 0, False
        return ("", "", 0, False)


def _orchestrate(monkeypatch, tmp_path, run_outcome, runner):
    """Run a single-container dynamic test through the runner's real body
    (the production entry point, passed by the caller), faking only the file
    writes and the docker subprocess."""
    rec = _FakeDocker(run_outcome)
    monkeypatch.setattr(de, "_run_command", rec)
    monkeypatch.setattr(de, "_write_test_files", lambda *a, **k: None)
    monkeypatch.setenv("OPENANT_DOCKER_REGISTRY_DIR", str(tmp_path / "registry"))
    result = runner({"language": "python", "code": "print(1)"}, "VULN-001")
    return rec, result


def _run_argv(recorder):
    return [c for c in recorder.calls if c[:2] == ["docker", "run"]][0]


def _rm_calls(recorder):
    return [c for c in recorder.calls if c[:3] == ["docker", "rm", "-f"]]


def test_a_timed_out_run_kills_the_owned_container(monkeypatch, tmp_path):
    """The RED witness: on a timeout a `docker rm -f <name>` must fire after
    the run — subprocess's timeout kills only the client, and `--rm` is
    daemon-side, so without an explicit teardown the container leaks."""
    rec, result = _orchestrate(
        monkeypatch, tmp_path, ("", "Command timed out", -1, True),
        runner=de.run_single_container)
    assert result.timed_out is True
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, (
        "the container must be named at run time — a container nobody can "
        "address is a container nobody can tear down (#732)"
    )
    name = run_cmd[run_cmd.index("--name") + 1]
    assert name.startswith("openant-test-"), "the run's own UUID naming model"
    rm = _rm_calls(rec)
    assert rm and rm[-1][-1] == "a" * 64, (
        "a timed-out run must remove the ownership-verified container it started "
        "(subprocess timeout kills only the client; --rm is daemon-side)"
    )
    assert rec.calls.index(rm[-1]) > rec.calls.index(run_cmd), (
        "the teardown must come after the run invocation"
    )


def test_the_name_reuses_the_run_naming_model(monkeypatch, tmp_path):
    """The container name carries the same run_id+safe_id as the image tag —
    the module's own UUID collision model (#315), not a new scheme."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, "the container must be named at run time"
    name = run_cmd[run_cmd.index("--name") + 1]
    image = run_cmd[-1]
    m_name = re.fullmatch(r"openant-test-([0-9a-f]{32})-(.+)", name)
    m_image = re.fullmatch(r"openant-test-([0-9a-f]{32})-(.+)", image)
    assert m_name and m_image, "both names follow the module's UUID model"
    assert m_name.group(2) == "vuln-001", "the safe_id derives from the finding"
    assert m_name.group(1) == m_image.group(1), "same run_id"
    assert m_name.group(2) == m_image.group(2), "same safe_id"


def test_a_normal_exit_still_tears_down_best_effort(monkeypatch, tmp_path):
    """The rm fires on every exit path (the compose path's down does too): on
    a normal exit `--rm` already removed the container and the rm is a
    harmless best-effort error, ignored like every cleanup call."""
    rec, result = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                               runner=de.run_single_container)
    assert result.timed_out is False
    assert "--name" in _run_argv(rec), "the container must be named at run time"
    assert _rm_calls(rec), "the teardown fires on every exit path"


def test_the_sandbox_flags_are_unchanged(monkeypatch, tmp_path):
    """The fix ADDS --name only: every F4/sandbox flag stays in the argv and
    --user stays out (the read-only-HOME breakage, per the reconstruct test)."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, "the container must be named at run time"
    s = " ".join(run_cmd)
    for flag in ("--rm", "--network none", "--memory 512m", "--cpus 1",
                 "--pids-limit 256", "--cap-drop ALL", "--read-only",
                 "--security-opt no-new-privileges"):
        assert flag in s, f"the sandbox flag {flag} must be unchanged"
    assert "--user" not in run_cmd, "must NOT pin --user (read-only-HOME breakage)"


def test_the_teardown_survives_an_exception_from_the_run(monkeypatch, tmp_path):
    """The FINALLY discipline (fable round-1 F1): the rm must fire even when
    the `docker run` call RAISES (not merely times out — a crash between run
    and result must not leak the container either). A plain sequential
    teardown (no try/finally) must FAIL this test."""
    rec, result = _orchestrate(monkeypatch, tmp_path,
        RuntimeError("docker client crashed mid-run"), runner=de.run_single_container)
    assert result.infrastructure_error
    assert "docker client crashed mid-run" in result.execution_error
    # the run raised; the finally must still have torn the container down
    assert _rm_calls(rec), (
        "an exception from the run must not skip the container teardown "
        "— the teardown lives in a finally, not in the happy path"
    )


def test_the_teardown_precedes_the_outer_image_cleanup(monkeypatch, tmp_path):
    """The ORDER discipline (fable round-1 F1): the container rm must run
    BEFORE removal of its image tag; removing an in-use image first
    can leave dangling layers."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    calls = rec.calls
    rm_idx = [i for i, c in enumerate(calls) if c[:3] == ["docker", "rm", "-f"]]
    rmi_idx = [i for i, c in enumerate(calls) if c[:3] == ["docker", "image", "rm"]]
    assert rm_idx and rmi_idx, "both the container rm and the image rmi fire"
    assert rm_idx[0] < rmi_idx[0], (
        "the container teardown must precede the image cleanup — an "
        "in-use image cannot be removed before its container"
    )


def test_the_container_uses_the_explicit_image_run_identity(monkeypatch, tmp_path):
    """No second independently generated container identity may drift."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    cmd = _run_argv(rec)
    assert cmd[cmd.index("--name") + 1] == cmd[-1]
