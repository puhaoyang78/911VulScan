"""按仓库构建一个"依赖已装好"的镜像，供每条发现的测试镜像复用。

此前只有 C/C++ 有共享工具链；Python/Node/Go 的依赖要在**每条发现**的
Dockerfile 里重新装一遍。层缓存能命中时看不出问题，一旦模型把 ``COPY . .``
写在安装命令之前、或缓存被清掉，每条发现都要重新等一遍 npm/pip/go 下载。

这里的做法与工具链一致：以仓库自己的清单文件为输入，构建一次

    vulscan/deps-<language>:<清单内容摘要>

之后每条发现的 Dockerfile 只要 ``FROM`` 这个镜像，依赖就已经在标准位置上，
不必再装。摘要取自清单文件内容，清单不变就直接复用；清单变了自然换 tag。

构建失败不是致命错误：拿不到依赖镜像时返回 ``None``，生成器继续按原有方式
在 Dockerfile 里安装依赖，整批扫描不受影响。
"""

from dataclasses import dataclass
import hashlib
import os
import re
import shutil
import sys
import tempfile

_PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")


@dataclass(frozen=True)
class DependencyPlan:
    """一个仓库的依赖安装方案（语言、基础镜像、清单、安装命令）。"""

    language: str
    base_image: str
    tag: str
    manifests: tuple[str, ...]
    install_command: str
    workdir: str
    # 写进提示词的一句话：依赖装在哪、不要再装一遍。
    prompt_note: str


def _read_text(path: str, limit: int = 200_000) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _digest(root: str, files: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for name in files:
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(_read_text(os.path.join(root, name)).encode("utf-8", "replace"))
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def _prefer_cached(candidates: list[str], available: tuple[str, ...]) -> str:
    """优先用本机已有镜像：拉取由守护进程完成，未缓存的镜像可能直接拉不下来。"""
    cached = set(available)
    for name in candidates:
        if name in cached:
            return name
    for name in candidates:
        repository = name.split(":", 1)[0] + ":"
        if any(item.startswith(repository) for item in cached):
            return name
    return candidates[0]


def _python_base(root: str, available: tuple[str, ...] = ()) -> str:
    pinned = _read_text(os.path.join(root, ".python-version")).strip().splitlines()
    match = re.fullmatch(r"(\d+\.\d+)(?:\.\d+)?", pinned[0].strip()) if pinned else None
    version = match.group(1) if match else "3.12"
    return _prefer_cached(
        [f"python:{version}-slim-bookworm", f"python:{version}-slim",
         "python:3.12-slim-bookworm", "python:3.12-slim"],
        available,
    )


def _go_base(root: str, available: tuple[str, ...] = ()) -> str:
    match = re.search(r"(?m)^go\s+(\d+\.\d+)", _read_text(os.path.join(root, "go.mod")))
    version = match.group(1) if match else "1.22"
    return _prefer_cached(
        [f"golang:{version}-alpine", f"golang:{version}",
         "golang:1.26-alpine", "golang:alpine"],
        available,
    )


def plan_for_repository(language: str, repo_root: str | None,
                        available: tuple[str, ...] = ()) -> DependencyPlan | None:
    """按语言给出依赖方案；没有清单或语言不在支持范围内时返回 ``None``。"""
    if not repo_root or not os.path.isdir(repo_root):
        return None
    lang = (language or "").strip().lower()
    if lang in ("python", "py"):
        manifests = tuple(name for name in ("requirements.txt", "pyproject.toml")
                          if os.path.isfile(os.path.join(repo_root, name)))
        if not manifests:
            return None
        if "requirements.txt" in manifests:
            install = "python -m pip install --no-cache-dir -r requirements.txt"
        else:
            install = "python -m pip install --no-cache-dir ."
        return DependencyPlan(
            language="python", base_image=_python_base(repo_root, available),
            tag=f"vulscan/deps-python:{_digest(repo_root, manifests)}",
            manifests=manifests, install_command=install, workdir="/app",
            prompt_note=("依赖已装在系统 site-packages；镜像里没有应用源码，"
                         "仍需 COPY 目标代码。不要再执行 pip install。"),
        )
    if lang in ("javascript", "js", "typescript", "ts", "node"):
        manifests = tuple(name for name in ("package.json", "package-lock.json",
                                            "npm-shrinkwrap.json")
                          if os.path.isfile(os.path.join(repo_root, name)))
        if "package.json" not in manifests:
            return None
        install = ("npm ci --no-audit --no-fund" if "package-lock.json" in manifests
                   else "npm install --no-audit --no-fund")
        return DependencyPlan(
            language="node",
            base_image=_prefer_cached(["node:20-slim", "node:24-slim", "node:22-slim"], available),
            tag=f"vulscan/deps-node:{_digest(repo_root, manifests)}",
            manifests=manifests, install_command=install, workdir="/app",
            prompt_note=("依赖已装在 /app/node_modules（并已设置 NODE_PATH）；镜像里没有"
                         "应用源码，仍需 COPY 目标代码。不要再执行 npm install。"),
        )
    if lang in ("go", "golang"):
        manifests = tuple(name for name in ("go.mod", "go.sum")
                          if os.path.isfile(os.path.join(repo_root, name)))
        if "go.mod" not in manifests:
            return None
        return DependencyPlan(
            language="go", base_image=_go_base(repo_root, available),
            tag=f"vulscan/deps-go:{_digest(repo_root, manifests)}",
            manifests=manifests, install_command="go mod download", workdir="/src",
            prompt_note=("依赖已下载到 /go/pkg/mod（GOMODCACHE 已设置）；镜像里没有"
                         "应用源码，仍需 COPY 目标代码。不要再执行 go mod download。"),
        )
    return None


def _image_present(tag: str, runner) -> bool:
    out, _err, code, timed = runner(
        ["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=60)
    return code == 0 and not timed and bool(out.strip())


def _dockerfile(plan: DependencyPlan) -> str:
    copies = " ".join(plan.manifests)
    env = ""
    toolchain = ""
    if plan.language == "node":
        env = "ENV NODE_PATH=/app/node_modules\n"
        # 原生模块（better-sqlite3、bcrypt、sqlite3…）需要 node-gyp 的编译工具，
        # 瘦身镜像默认没有；缺了它们 npm install 会直接失败。
        toolchain = ("RUN apt-get update \\\n"
                     " && apt-get install -y --no-install-recommends python3 make g++ \\\n"
                     " && rm -rf /var/lib/apt/lists/*\n")
    elif plan.language == "go":
        env = "ENV GOMODCACHE=/go/pkg/mod GOFLAGS=-mod=mod\n"
    return (f"FROM {plan.base_image}\n"
            f"{toolchain}"
            f"WORKDIR {plan.workdir}\n"
            f"{env}"
            f"COPY {copies} ./\n"
            f"RUN {plan.install_command}\n")


def ensure_dependency_image(
    plan: DependencyPlan,
    repo_root: str,
    runner,
    proxy_arguments=(),
    build_timeout: int = 900,
) -> str | None:
    """构建（或复用）依赖镜像；失败只告警并返回 ``None``。"""
    if _image_present(plan.tag, runner):
        return plan.tag

    context = tempfile.mkdtemp(prefix="vulscan-deps-")
    try:
        for name in plan.manifests:
            shutil.copy2(os.path.join(repo_root, name), os.path.join(context, name))
        with open(os.path.join(context, "Dockerfile"), "w", encoding="utf-8") as handle:
            handle.write(_dockerfile(plan))
        argv = ["docker", "build", "--builder", "default",
                "-t", plan.tag, "-f", os.path.join(context, "Dockerfile"), context]
        argv.extend(proxy_arguments)
        out, err, code, timed = runner(argv, timeout=build_timeout)
        if code == 0 and not timed:
            print(f"  依赖镜像已就绪：{plan.tag}", file=sys.stderr)
            return plan.tag
        diagnostic = (err or out or "").strip().splitlines()
        tail = diagnostic[-1] if diagnostic else ""
        print(f"  依赖镜像构建失败，退回逐条安装：{tail[:160]}", file=sys.stderr)
        return None
    finally:
        shutil.rmtree(context, ignore_errors=True)
