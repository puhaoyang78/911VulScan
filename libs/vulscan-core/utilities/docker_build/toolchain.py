"""共享工具链镜像：一次构建，全部发现与全部运行复用。

C/C++ 复现模板原先在**每条发现**的 Dockerfile 里执行
``apt-get install gcc g++ libc6-dev``（约 63 MiB）。一旦某次构建在下载途中超时，
BuildKit 不会提交任何层，下一次发现又从零开始下载，于是一次网络抖动就能让整批
发现连续失败。工具链镜像把这份下载变成宿主级的一次性准备工作：

* 镜像内容由 VulScan 自己的 Dockerfile 决定，不经过模型，也不受目标仓库影响；
* 标签携带 Dockerfile 内容的摘要，配方改动会自动产生新标签，不会误用旧镜像；
* 镜像不带 owner/run 标签，因此按标签回收发现的清理逻辑不会删掉它。

基础镜像拉取与依赖下载同样走用户选择的构建代理。
"""

from dataclasses import dataclass
import hashlib
import os

from utilities.docker_build.errors import DockerBuildEnvironmentError

_TEMPLATES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dynamic_tester", "docker_templates",
)

# 原生（编译型）语言到工具链配方目录的映射。C 与 C++ 共用同一个 gcc/g++ 工具链。
_RECIPES = {"c": "toolchain-c"}
_SUPPORTED_NATIVE = frozenset({"c", "cpp"})


@dataclass(frozen=True)
class Toolchain:
    """一个可复用的工具链镜像。``image`` 只由配方内容决定，因此跨运行稳定。"""

    language: str
    image: str
    context: str
    dockerfile: str

    def base_line(self) -> str:
        return f"FROM {self.image}"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def native_toolchain(language: str) -> Toolchain:
    """返回该语言对应的工具链镜像定义（不触发任何 Docker 调用）。"""
    if language not in _SUPPORTED_NATIVE:
        raise ValueError(f"没有可用的原生工具链配方：{language}")
    context = os.path.join(_TEMPLATES, _RECIPES["c"])
    path = os.path.join(context, "Dockerfile")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise DockerBuildEnvironmentError(f"工具链配方缺失：{path}（{exc}）") from exc
    image = f"vulscan/{_RECIPES['c']}:gcc12-{_digest(text)}"
    return Toolchain(language="c", image=image, context=context, dockerfile=path)


_CONSUMER_TEMPLATE = os.path.join(_TEMPLATES, "c.Dockerfile")
_PLACEHOLDER = "{{VULSCAN_TOOLCHAIN}}"


def render_native_dockerfile(language: str) -> str:
    """按工具链镜像渲染单文件复现用的 Dockerfile（不触发 Docker 调用）。

    模板里只有一个占位符：基础镜像。模型提供的 dockerfile 会被执行器替换成
    这份文本，因此这里也是提示词与执行器的同一份定义。
    """
    toolchain = native_toolchain(language)
    try:
        with open(_CONSUMER_TEMPLATE, encoding="utf-8") as handle:
            template = handle.read()
    except OSError as exc:
        raise DockerBuildEnvironmentError(f"复现模板缺失：{_CONSUMER_TEMPLATE}（{exc}）") from exc
    return template.replace(_PLACEHOLDER, toolchain.image)


def _present(image: str, runner) -> bool:
    out, _err, code, timed = runner(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=60)
    return code == 0 and not timed and bool(out.strip())


def ensure_toolchain(toolchain: Toolchain, runner, proxy_arguments=(), timeout: int = 1800) -> str:
    """确保工具链镜像存在；不存在则构建一次。返回镜像引用。

    调用方必须已经持有 Docker 构建准入锁（``docker_resources.build_admission``），
    否则并发运行会同时构建同一份工具链。
    """
    if _present(toolchain.image, runner):
        return toolchain.image
    command = [
        "docker", "build", "--builder", "default",
        "-t", toolchain.image,
        # 只标记为 VulScan 工具链；不带 owner/run 标签，避免被按发现回收时删除。
        "--label", "io.vulscan.toolchain=1",
        *proxy_arguments,
        ".",
    ]
    out, err, code, timed = runner(command, timeout=timeout, cwd=toolchain.context)
    if code == 0 and not timed:
        return toolchain.image
    diagnostic = "\n".join(part for part in (out, err) if part)
    reason = "构建超时" if timed else f"构建退出码 {code}"
    raise DockerBuildEnvironmentError(
        f"共享工具链镜像 {toolchain.image} 无法准备（{reason}）。"
        "首次构建需要下载编译器与基础镜像；请检查网络，或为 Docker 构建配置代理。\n"
        + diagnostic[-4000:]
    )
