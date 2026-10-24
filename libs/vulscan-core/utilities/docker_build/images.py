"""基础镜像：本机清单与按需拉取。

``--build-arg HTTP_PROXY`` 只影响 ``RUN`` 步骤，镜像**解析**（pull）由守护进程自己
完成，构建参数管不到。因此模型生成的 ``FROM python:3.11-slim`` 在本机没有缓存时，
即使代理填对了也会因为拉取失败而整条发现记 ERROR；而失败发生在构建阶段，重写
测试毫无用处，旧的重试循环还要为此烧掉三次模型调用。

这里做两件确定的事：

* 读取本机已有镜像，交给生成提示词，让模型优先选择已缓存的基础镜像；
* 构建前解析 Dockerfile 的 ``FROM``，只对缺失的镜像执行一次 ``docker pull``，
  失败立即给出可操作的中文说明，不进入模型重试。
"""

from dataclasses import dataclass
import os
import re

from utilities.docker_build.errors import DockerBuildEnvironmentError

_LIST = ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]
# 形如 FROM [--platform=...] image[:tag|@digest] [AS name]
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)
_SKIP_BASES = {"scratch"}
_REGISTRY_HINTS = (
    "failed to resolve source metadata",
    "failed to fetch anonymous token",
    "failed to authorize",
    "pull access denied",
    "no such host",
    "i/o timeout",
    "tls handshake timeout",
    "connection refused",
    "network is unreachable",
)


@dataclass(frozen=True)
class PullResult:
    pulled: tuple[str, ...] = ()
    cached: tuple[str, ...] = ()


def is_registry_failure(text: str) -> bool:
    """构建日志是否表明是注册表/网络不可用（而不是 Dockerfile 内容错误）。"""
    lowered = (text or "").lower()
    return any(hint in lowered for hint in _REGISTRY_HINTS)


def available_images(runner, limit: int = 40) -> tuple[str, ...]:
    """本机 ``repo:tag`` 列表（不含 ``<none>``），用于提示词与日志。"""
    out, err, code, timed = runner(_LIST, timeout=60)
    if code or timed:
        return ()
    names = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("<none>"):
            continue
        names.append(line)
        if len(names) >= limit:
            break
    return tuple(names)


def dockerfile_bases(root: str, max_files: int = 8, *, compose: bool = False) -> tuple[str, ...]:
    """只解析本次构建实际使用的 Dockerfile，并排除已命名的构建阶段。

    扫描仓库的副本可能包含任意数量的 Dockerfile；它们不是本次验证的构建入口。
    对 Compose，只检查声明 build 的服务；image-only 服务直接准备镜像。
    """
    root = os.path.realpath(root)
    dockerfiles: list[str] = []
    images: list[str] = []

    def inside(path: str) -> str | None:
        resolved = os.path.realpath(path)
        if os.path.commonpath((root, resolved)) != root:
            return None
        return resolved

    if compose:
        import yaml
        path = os.path.join(root, "docker-compose.yml")
        with open(path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        for svc in config.get("services", {}).values():
            if not isinstance(svc, dict):
                continue
            build = svc.get("build")
            if build:
                context = build if isinstance(build, str) else build.get("context", ".")
                dockerfile = "Dockerfile" if isinstance(build, str) else build.get("dockerfile", "Dockerfile")
                if not isinstance(context, str) or not isinstance(dockerfile, str):
                    continue
                candidate = inside(os.path.join(root, context, dockerfile))
                if candidate and candidate not in dockerfiles:
                    dockerfiles.append(candidate)
            elif isinstance(svc.get("image"), str):
                images.append(svc["image"])
    else:
        dockerfiles.append(os.path.join(root, "Dockerfile"))

    for path in dockerfiles[:max_files]:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            dockerfile = handle.read()
        stages: set[str] = set()
        for line in dockerfile.splitlines():
            match = re.match(
                r"^\\s*FROM\\s+(?:--platform=\\S+\\s+)?(\\S+)(?:\\s+AS\\s+(\\S+))?",
                line, re.IGNORECASE,
            )
            if not match:
                continue
            image, alias = match.group(1), match.group(2)
            if (image.lower() not in stages and image.lower() not in _SKIP_BASES
                    and not image.startswith("$") and image not in images):
                images.append(image)
            if alias:
                stages.add(alias.lower())
    return tuple(images)


def _present(ref: str, runner) -> bool:
    out, _err, code, timed = runner(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref], timeout=60)
    return code == 0 and not timed and bool(out.strip())


def ensure_base_images(bases, runner, timeout: int = 600) -> PullResult:
    """拉取缺失的基础镜像；任一失败即抛出环境错误。

    顺序执行是刻意的：镜像层共享，并发拉取只会让日志与错误归属变复杂。
    """
    pulled, cached = [], []
    for ref in bases:
        if _present(ref, runner):
            cached.append(ref)
            continue
        out, err, code, timed = runner(["docker", "pull", ref], timeout=timeout)
        if code == 0 and not timed:
            pulled.append(ref)
            continue
        diagnostic = "\n".join(part for part in (out, err) if part)
        reason = "拉取超时" if timed else f"拉取退出码 {code}"
        raise DockerBuildEnvironmentError(
            f"基础镜像 {ref} 无法准备（{reason}）。镜像拉取由 Docker 守护进程完成，"
            "构建代理只影响构建步骤内的下载；请为该守护进程配置代理、在宿主机预先 "
            f"`docker pull {ref}`，或让生成结果改用本机已有镜像。\n"
            + diagnostic[-2000:]
        )
    return PullResult(pulled=tuple(pulled), cached=tuple(cached))
