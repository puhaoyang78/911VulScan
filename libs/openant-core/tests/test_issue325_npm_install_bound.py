"""#325: the npm-install bootstrap and its lock are bounded.

`_ensure_js_parser_dependencies` ran `npm install` with no `timeout=`, behind a
blocking `fcntl.flock(LOCK_EX)` with no acquisition deadline. A stalled npm hung its
process indefinitely AND every concurrent parse behind the lock it holds. PR #135 named
this exact call as a deferred follow-up; the source's own convention (the parse steps
use `timeout=1800`) never reached the bootstrap. The same gap class exists in the two
reporter subprocess calls (the issue's scope note: the convention was never extended
to the other call sites).

The fix (the issue's suggestions):
- `timeout=` on the npm install (a generous bound — the parse steps use 1800s —
  still converts an indefinite hang into a diagnosable failure);
- a BOUNDED lock acquisition (`LOCK_EX | LOCK_NB` in a retry loop with a deadline) so
  a wedged holder cannot block every other process without limit;
- the two reporter subprocesses carry the bound too (the issue's item 3).
"""
import sys
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from core import parser_adapter as pa  # noqa: E402
from core import reporter  # noqa: E402


def test_npm_install_has_a_timeout():
    """PR #135's named follow-up: the bootstrap call carries timeout=."""
    import inspect

    src = inspect.getsource(pa._ensure_js_parser_dependencies)
    j = src.find("_npm_proc.wait(")
    assert j > 0
    call_text = src[j:j + 300]
    assert "timeout=" in call_text, "the npm install carries no timeout"
    assert "1800" in call_text or "_NPM_INSTALL_TIMEOUT_S" in call_text


def test_file_lock_is_bounded():
    """The lock acquisition has a deadline — LOCK_NB + a retry loop, not a
    bare blocking LOCK_EX (a wedged holder blocked every process without
    limit)."""
    import inspect

    src = inspect.getsource(pa._file_lock)
    assert "LOCK_NB" in src, "no non-blocking acquisition — the wait is unbounded"
    assert "deadline" in src.lower() or "timeout" in src.lower(), "no retry deadline"


@pytest.mark.parametrize("report_format", ["html", "csv"])
def test_reporter_subprocesses_bounded(report_format, monkeypatch):
    """The issue's item 3: the two reporter subprocess calls (the HTML and
    CSV generation) carry the bound too."""
    from types import SimpleNamespace

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(reporter.subprocess, "run", fake_run)
    output_path = f"report.{report_format}"
    result = getattr(reporter, f"generate_{report_format}_report")(
        "results.json", "dataset.json", output_path)

    assert len(calls) == 1
    cmd, kwargs = calls[0]
    module = "report.html_report" if report_format == "html" else "report.csv_export"
    assert cmd[:4] == [sys.executable, "-P", "-m", module]
    assert kwargs["timeout"] == 1800, "the reporter subprocess must remain bounded"
    assert result.output_path == output_path
    assert result.format == report_format


def test_npm_install_timeout_error_is_diagnosable(tmp_path, monkeypatch):
    """Wave r1 (opus): the named diagnosis is EXECUTED, not asserted — a stub
    npm that sleeps past a small injected bound raises the named RuntimeError
    (the bound + the recovery), and its process group is killed with it (a
    killed npm must not leave a postinstall grandchild writing node_modules
    while the lock releases)."""
    import os
    import shutil as _shutil
    import stat

    if not _shutil.which("/bin/sh"):
        pytest.skip("/bin/sh not available")
    stub = tmp_path / "npm"
    stub.write_text("#!/bin/sh\nsleep 30\nexit 0\n")
    stub.chmod(stat.S_IRWXU)
    (tmp_path / "package.json").write_text('{"name": "stub", "dependencies": {}}')
    monkeypatch.setattr(pa, "_NPM_INSTALL_TIMEOUT_S", 1)
    monkeypatch.setattr(pa, "_JS_PARSER_DIR", tmp_path)
    monkeypatch.setattr(pa, "_js_deps_installed", lambda: False)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    real_which = pa.shutil.which

    def fake_which(name, path=None):
        if name == "npm":
            return str(stub)
        return real_which(name, path=path)

    monkeypatch.setattr(pa.shutil, "which", fake_which)
    with pytest.raises(RuntimeError, match="exceeded the 1s install bound"):
        pa._ensure_js_parser_dependencies()
    # the stub's process group is gone (no orphan sleeper)
    r = pa.subprocess.run(["pgrep", "-f", f"sleep 30"], capture_output=True, text=True)
    assert "sleep 30" not in (r.stdout or "")
