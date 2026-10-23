# Modified 2026-10-23 for the VulScan-only product namespace.
"""Compose teardown runs after build failure, timeout, and success.

Image cleanup is separately label-scoped; compose down must not delete shared
external images via --rmi.
"""
from __future__ import annotations

from unittest.mock import patch

from utilities.dynamic_tester.docker_executor import _run_compose


class _Recorder:
    def __init__(self, results):
        self._results = list(results)
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=None, cwd=None):
        self.calls.append(list(cmd))
        return self._results.pop(0)


def _seq(*outcomes):
    """Build the _run_command result sequence.

    outcomes: tuples (stdout, stderr, code, timed_out) in call order.
    """
    return [o for o in outcomes]


def test_build_failure_still_tears_down():
    """The #536 regression: partial builds must still run compose teardown."""
    # build fails, then (post-fix) the teardown runs.
    rec = _Recorder([
        ("", "failed to solve: exit 1", 1, False),   # docker compose build
        ("", "", 0, False),                           # docker compose down (teardown)
        ("", "", 0, False),                           # docker compose logs (defensive)
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "vulscan-abc12345-vuln-001", 60, 120)
    assert result.build_error  # the build failure is reported
    assert len(rec.calls) == 2, rec.calls  # build + teardown, nothing else
    downs = [c for c in rec.calls
             if "down" in c and "--volumes" in c]
    assert all("--rmi" not in c for c in rec.calls)
    assert len(downs) == 1, (
        f"a failed build must tear down; calls: {rec.calls}")


def test_build_timeout_still_tears_down():
    rec = _Recorder([
        ("", "", -1, True),                            # build times out
        ("", "", 0, False),                           # teardown
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "p", 60, 120)
    assert result.timed_out
    assert len(rec.calls) == 2, rec.calls
    downs = [c for c in rec.calls if "down" in c and "--volumes" in c]
    assert all("--rmi" not in c for c in rec.calls)
    assert len(downs) == 1


def test_success_path_teardown_unchanged():
    """The happy path tears down exactly once (in the existing finally)."""
    rec = _Recorder([
        ("", "", 0, False),   # build
        ("", "", 0, False),   # up -d
        ("log", "", 0, False),  # logs -f test
        ("", "", 0, False),   # down (finally)
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "p", 60, 120)
    assert result.exit_code == 0
    assert not result.build_error
    downs = [c for c in rec.calls if "down" in c and "--volumes" in c]
    assert all("--rmi" not in c for c in rec.calls)
    assert len(downs) == 1  # exactly one teardown — no double-down
