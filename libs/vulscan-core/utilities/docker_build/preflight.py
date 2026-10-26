"""构建前预检：在产生任何模型费用之前，确认宿主能真正构建。

没有预检时，代理填错或守护进程不可用会表现成“每条发现都卡满构建预算再报超时”，
一次运行可能因此损失几十分钟；而且错误被记在每条发现上，看不出是宿主问题。
预检把这类错误提前到阶段入口，只报一次，并给出可操作的中文说明。
"""

import shutil

from utilities.docker_build.errors import DockerBuildEnvironmentError
from utilities.docker_build.proxy import describe_proxy, probe_proxy

_DAEMON_PROBE = ["docker", "version", "--format", "{{.Server.Version}}"]
# `--builder` 由 buildx 提供；缺失时构建命令会以 "unknown flag" 失败，属于宿主问题。
_BUILDX_PROBE = ["docker", "buildx", "version"]


def verify_build_environment(proxy: str | None, runner, *, language: str = "") -> dict:
    """检查 docker CLI、守护进程、buildx 与代理可达性。返回可记录的摘要。

    Raises:
        DockerBuildEnvironmentError: 任一前置条件不满足（与目标代码无关）。
    """
    if not shutil.which("docker"):
        raise DockerBuildEnvironmentError(
            "动态验证需要 Docker，但当前未找到 docker 可执行文件。"
            "请安装并启动 Docker；VulScan 不会在宿主机直接运行目标代码。")

    out, err, code, timed = runner(_DAEMON_PROBE, timeout=30)
    if code or timed:
        detail = (err or out or f"退出码 {code}")[:800]
        raise DockerBuildEnvironmentError(
            f"Docker 守护进程不可用：{detail}。请确认 Docker Engine 已启动，"
            "并检查当前用户是否有访问权限。")

    _out, err, code, timed = runner(_BUILDX_PROBE, timeout=30)
    if code or timed:
        detail = (err or _out or f"退出码 {code}")[:800]
        raise DockerBuildEnvironmentError(
            f"Docker buildx 不可用：{detail}。二阶段构建固定使用默认 builder，"
            "请安装 buildx 插件后重试。")

    # A listening port alone was insufficient: an unusable upstream passed
    # preflight and then spent the full build budget downloading dependencies.
    dependency_source = {
        "python": "https://pypi.org/simple/",
        "javascript": "https://registry.npmjs.org/",
        "typescript": "https://registry.npmjs.org/",
        "go": "https://proxy.golang.org/",
    }.get(language.lower() if isinstance(language, str) else "")
    probe_proxy(proxy, target=dependency_source)
    return {
        "server_version": out.strip(),
        "proxy": proxy or "",
        "proxy_description": describe_proxy(proxy),
    }
