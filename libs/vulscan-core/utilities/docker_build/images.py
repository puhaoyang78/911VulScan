"""本机基础镜像优先复用；缺失时先国内源，再通过任务代理获取官方源。"""

from dataclasses import dataclass
import os
import re
import sys
from string import Template
import time

from utilities.docker_build.errors import DockerBuildEnvironmentError
from utilities.docker_build.registry import image_reference, pull_via_proxy
from utilities.docker_build.proxy import parse_docker_proxy

_LIST = ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]
_SKIP_BASES = {"scratch"}
_MIRROR = "m.daocloud.io"
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
    replacements: tuple[tuple[str, str], ...] = ()


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


def build_inputs(root: str, *, compose: bool = False) -> tuple[list[str], list[str]]:
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

    return dockerfiles, images


def _base_references(text: str):
    """返回外部 FROM 的原文位置与已解析引用，供预拉取和摘要替换共用。"""
    stages: set[str] = set()
    arguments: dict[str, str] = {}
    seen_from = False
    offset = 0
    for line in text.splitlines(keepends=True):
        argument = re.match(r'^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$', line.rstrip(), re.I)
        if argument and not seen_from:
            name, value = argument.groups()
            if value is not None:
                arguments[name] = Template(value.strip().strip('"\'')).safe_substitute(arguments)
        match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if match:
            seen_from = True
            image = Template(match.group(1)).safe_substitute(arguments)
            if '$' in image:
                raise DockerBuildEnvironmentError(f"无法确定 Dockerfile 的基础镜像变量：{match.group(1)}；请在 ARG 中声明默认值")
            if image.lower() not in stages and image.lower() not in _SKIP_BASES:
                yield offset + match.start(1), offset + match.end(1), image
            if match.group(2):
                stages.add(match.group(2).lower())
        offset += len(line)


def dockerfile_bases(root: str, max_files: int = 8, *, compose: bool = False) -> tuple[str, ...]:
    dockerfiles, images = build_inputs(root, compose=compose)
    for path in dockerfiles[:max_files]:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            for _, _, image in _base_references(handle.read()):
                if image not in images:
                    images.append(image)
    return tuple(images)


def _present(ref: str, runner) -> bool:
    out, _err, code, timed = runner(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref], timeout=60)
    return code == 0 and not timed and bool(out.strip())


def log_download(message: str, *, status: str = "running") -> None:
    print("  [Docker 下载] " + message, file=sys.stderr, flush=True)
    from core import ui_events
    ui_events.emit("activity", stage="dynamic-test", phase="environment", status=status, message=message)


def ensure_base_images(bases, runner, timeout: int = 600, *, proxy: str | None = None) -> PullResult:
    """每个镜像最多一次国内拉取、一次官方代理拉取，不改变 daemon 的配置。"""
    proxy = parse_docker_proxy(proxy)
    pulled, cached, replacements = [], [], []
    for ref in bases:
        if _present(ref, runner):
            log_download(f"本机镜像缓存命中：{ref}", status="success")
            cached.append(ref)
            continue
        registry, repository, version = image_reference(ref)
        if '@' in ref:
            local = 'vulscan/base-cache:' + version.removeprefix('sha256:')
            if _present(local, runner):
                cached.append(ref)
                replacements.append((ref, local))
                log_download(f"已校验摘要的本机镜像缓存命中：{ref}", status="success")
                continue
        mirror = f"{_MIRROR}/{registry}/{repository}" + ('@' if '@' in ref else ':') + version
        deadline = time.monotonic() + timeout
        log_download(f"国内镜像源：{mirror}")
        mirror_cached = _present(mirror, runner)
        if mirror_cached:
            log_download(f"国内镜像引用的本机缓存命中：{mirror}", status="success")
            out, err, code, timed = '', '', 0, False
        else:
            out, err, code, timed = runner(["docker", "pull", mirror], timeout=min(90, timeout / 2 if proxy else timeout))
        if code == 0 and not timed:
            if '@' in ref:
                local = 'vulscan/base-cache:' + version.removeprefix('sha256:')
            else:
                local = ref
            _out, _err, tag_code, tag_timed = runner(['docker', 'tag', mirror, local], timeout=30)
            if tag_code or tag_timed:
                raise DockerBuildEnvironmentError('国内镜像已拉取但创建本地引用失败：' + (_err or _out))
            if local != ref:
                replacements.append((ref, local))
            log_download(f"国内镜像源成功：{ref}，未启用任务代理", status="success")
            (cached if mirror_cached else pulled).append(ref)
            continue
        diagnostic = "\n".join(part for part in (out, err) if part)
        reason = "拉取超时" if timed else f"拉取退出码 {code}"
        log_download(f"国内镜像源失败：{mirror}（{reason}）；{diagnostic[-1200:]}", status="error")
        if not proxy:
            raise DockerBuildEnvironmentError(
                f"基础镜像 {ref} 的国内源不可用，尚未配置 Docker 代理；未访问官方源。\n" + diagnostic[-2000:])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DockerBuildEnvironmentError(f"基础镜像 {ref} 的拉取总预算已耗尽")
        log_download(f"切换官方镜像源 {registry}/{repository}，使用任务代理 {proxy}（仅此一次）")
        local = pull_via_proxy(ref, proxy, runner, remaining)
        if local != ref:
            replacements.append((ref, local))
        pulled.append(ref)
        log_download(f"官方镜像代理下载、摘要校验与导入成功：{ref}", status="success")
    return PullResult(pulled=tuple(pulled), cached=tuple(cached), replacements=tuple(replacements))


def replace_base_references(root: str, replacements, *, compose: bool = False) -> None:
    """只有已校验的摘要镜像需要改为本地引用；不改变版本或阶段名。"""
    if not replacements:
        return
    mapping = dict(replacements)
    paths, _ = build_inputs(root, compose=compose)
    for path in paths:
        with open(path, encoding='utf-8') as handle:
            text = handle.read()
        for start, end, image in reversed(list(_base_references(text))):
            if image in mapping:
                text = text[:start] + mapping[image] + text[end:]
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    if compose:
        import yaml
        path = os.path.join(root, 'docker-compose.yml')
        with open(path, encoding='utf-8') as handle:
            data = yaml.safe_load(handle)
        for service in data.get('services', {}).values():
            if isinstance(service, dict) and not service.get('build') and service.get('image') in mapping:
                service['image'] = mapping[service['image']]
        with open(path, 'w', encoding='utf-8') as handle:
            yaml.safe_dump(data, handle, sort_keys=False)
