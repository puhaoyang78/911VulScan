"""二阶段构建环境的层次化契约：时间预算、工具链缓存、预检与失败分类。"""

import pytest

from utilities.docker_build import (
    BUILD,
    BUILD_TIMEOUT,
    CLEANUP,
    ENVIRONMENT,
    RUN_TIMEOUT,
    STAGING,
    TOOLCHAIN,
    BuildPolicy,
    DockerBuildEnvironmentError,
    ensure_toolchain,
    native_toolchain,
    render_native_dockerfile,
)
from utilities.docker_build import preflight as preflight_module
from utilities.dynamic_tester.docker_executor import DockerExecutionResult
from utilities.dynamic_tester.result_collector import collect_result


# --------------------------------------------------------------------------- policy

def test_policy_defaults_fit_dependency_downloads():
    policy = BuildPolicy.from_environment({})
    assert policy.build_timeout >= 600, "一次依赖下载不应正好卡在旧的三百秒上"
    assert policy.toolchain_timeout >= policy.build_timeout
    assert policy.run_timeout == 120


@pytest.mark.parametrize("name", ["VULSCAN_DOCKER_BUILD_TIMEOUT",
                                 "VULSCAN_DOCKER_RUN_TIMEOUT",
                                 "VULSCAN_DOCKER_TOOLCHAIN_TIMEOUT"])
@pytest.mark.parametrize("value", ["abc", "0", "-5", "1.5"])
def test_policy_rejects_invalid_override(name, value):
    with pytest.raises(ValueError, match=name):
        BuildPolicy.from_environment({name: value})


def test_policy_reads_overrides_and_reports_retryability():
    policy = BuildPolicy.from_environment({"VULSCAN_DOCKER_BUILD_TIMEOUT": "42"},
                                          run_timeout=7)
    assert (policy.build_timeout, policy.run_timeout) == (42, 7)
    assert policy.retry_allowed(BUILD) is True
    assert policy.retry_allowed(STAGING) is True
    for kind in (BUILD_TIMEOUT, RUN_TIMEOUT, TOOLCHAIN, ENVIRONMENT, CLEANUP):
        assert policy.retry_allowed(kind) is False


# ------------------------------------------------------------------------ toolchain

def test_toolchain_image_is_content_addressed_and_stable():
    first, second = native_toolchain("c"), native_toolchain("cpp")
    assert first.image == second.image
    assert first.image.startswith("vulscan/toolchain-c:gcc12-")
    with open(first.dockerfile, encoding="utf-8") as handle:
        recipe = handle.read()
    assert "apt-get install" in recipe, "工具链镜像本身才是安装编译器的地方"


def test_rendered_dockerfile_reuses_the_shared_toolchain():
    text = render_native_dockerfile("cpp")
    assert f"FROM {native_toolchain('cpp').image}" in text
    assert "apt-get" not in text, "每条发现的构建不应重复安装编译器"
    assert "{{" not in text


def test_toolchain_is_reused_when_the_image_exists():
    calls = []
    runner = lambda command, **kwargs: (calls.append(command) or ("sha256:abc", "", 0, False))
    assert ensure_toolchain(native_toolchain("c"), runner) == native_toolchain("c").image
    assert len(calls) == 1 and calls[0][:3] == ["docker", "image", "inspect"]


def test_toolchain_is_built_once_with_proxy_and_shared_label():
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["docker", "image", "inspect"]:
            return "", "Error: No such image", 1, False
        return "", "done", 0, False

    ensure_toolchain(native_toolchain("c"), runner,
                     proxy_arguments=["--build-arg", "HTTP_PROXY=http://10.0.0.2:3128"],
                     timeout=600)
    build, kwargs = calls[1]
    assert build[:4] == ["docker", "build", "--builder", "default"]
    assert "io.vulscan.toolchain=1" in build
    assert "HTTP_PROXY=http://10.0.0.2:3128" in build
    assert kwargs["timeout"] == 600
    # 共享镜像绝不能带按发现回收的 owner/run 标签。
    assert not any("io.vulscan.owner=" in part for part in build)


def test_toolchain_failure_is_an_environment_error():
    def runner(command, **kwargs):
        if command[:3] == ["docker", "image", "inspect"]:
            return "", "No such image", 1, False
        return "", "failed to solve: network unreachable", 1, False
    with pytest.raises(DockerBuildEnvironmentError, match="工具链镜像"):
        ensure_toolchain(native_toolchain("c"), runner, timeout=10)


# ------------------------------------------------------------------------ preflight



@pytest.fixture
def docker_present(monkeypatch):
    monkeypatch.setattr(preflight_module.shutil, "which", lambda name: "/usr/bin/docker")


def _runner(*responses):
    remaining = list(responses)
    def run(command, **kwargs):
        return remaining.pop(0) if remaining else ("", "", 0, False)
    return run


def test_preflight_reports_unreachable_daemon(docker_present):
    runner = _runner(("", "Cannot connect to the Docker daemon", 1, False))
    with pytest.raises(DockerBuildEnvironmentError, match="守护进程"):
        preflight_module.verify_build_environment(None, runner)


def test_preflight_reports_missing_buildx(docker_present):
    runner = _runner(("26.1.3", "", 0, False), ("", "docker: 'buildx' is not a docker command", 1, False))
    with pytest.raises(DockerBuildEnvironmentError, match="buildx"):
        preflight_module.verify_build_environment(None, runner)


def test_preflight_accepts_a_reachable_proxy(docker_present):
    import socket
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        port = listener.getsockname()[1]
        runner = _runner(("26.1.3", "", 0, False), ("v0.13.2", "", 0, False))
        report = preflight_module.verify_build_environment(f"http://127.0.0.1:{port}", runner)
        assert report["proxy"] == f"http://127.0.0.1:{port}"
        assert report["server_version"] == "26.1.3"
    finally:
        listener.close()


def test_preflight_rejects_an_unreachable_proxy(docker_present):
    runner = _runner(("26.1.3", "", 0, False), ("v0.13.2", "", 0, False))
    with pytest.raises(DockerBuildEnvironmentError, match="构建代理无法连接"):
        preflight_module.verify_build_environment("http://127.0.0.1:9", runner)


# ------------------------------------------------------------------ failure taxonomy

def test_execution_result_derives_flags_from_the_failure_kind():
    timeout = DockerExecutionResult().fail(BUILD_TIMEOUT, "log", timed_out=True)
    assert (timeout.failure_kind, timeout.timed_out) == (BUILD_TIMEOUT, True)
    assert timeout.build_error == "log" and timeout.execution_error is None
    assert timeout.retryable is False and timeout.infrastructure_error is False

    environment = DockerExecutionResult().fail(ENVIRONMENT, "no daemon")
    assert environment.infrastructure_error is True and environment.retryable is False
    assert environment.build_error is None


def test_build_timeout_is_reported_as_such_and_not_retried():
    execution = DockerExecutionResult().fail(BUILD_TIMEOUT, "apt-get timed out", timed_out=True)
    result = collect_result({"id": "V-1"}, {"test_script": "x", "dockerfile": "y"}, execution)
    assert result.status == "ERROR"
    assert result.details.startswith("Docker 构建超时：")
    assert "容器执行超时" not in result.details


def test_container_timeout_stays_inconclusive():
    execution = DockerExecutionResult().fail(RUN_TIMEOUT, "", timed_out=True, exit_code=-1)
    result = collect_result({"id": "V-1"}, {"test_script": "x", "dockerfile": "y"}, execution)
    assert result.status == "INCONCLUSIVE"
    assert execution.retryable is False and execution.execution_error is None


def test_proxy_probes_real_dependency_source_not_only_listening_port(monkeypatch):
    from utilities.docker_build import proxy
    calls = []
    class Connection:
        def __init__(self, host, port, timeout):
            calls.append((host, port, timeout))
        def set_tunnel(self, host, port):
            calls.append(('CONNECT', host, port))
        def request(self, method, path, headers):
            calls.append((method, path))
        def getresponse(self):
            from types import SimpleNamespace
            return SimpleNamespace(status=200)
        def close(self):
            calls.append('closed')
    monkeypatch.setattr(proxy.http.client, 'HTTPSConnection', Connection)
    proxy.probe_proxy('http://127.0.0.1:7890', target='https://pypi.org/simple/')
    assert calls == [('127.0.0.1', 7890, 5.0), ('CONNECT', 'pypi.org', 443), ('HEAD', '/simple/'), 'closed']


def test_proxy_dependency_timeout_closes_and_does_not_fall_back(monkeypatch):
    from utilities.docker_build import proxy
    closed = []
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def set_tunnel(self, *args): pass
        def request(self, *args, **kwargs): raise TimeoutError('upstream timed out')
        def close(self): closed.append(True)
    monkeypatch.setattr(proxy.http.client, 'HTTPSConnection', Connection)
    with pytest.raises(DockerBuildEnvironmentError, match='pypi.org'):
        proxy.probe_proxy('http://127.0.0.1:7890', target='https://pypi.org/simple/')
    assert closed == [True]
