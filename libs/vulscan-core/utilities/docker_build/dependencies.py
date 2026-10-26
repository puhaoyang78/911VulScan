"""按运行时、构建配方和完整依赖清单复用依赖镜像，不复制应用源码。"""

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import sys
import tempfile
import tomllib

from utilities.docker_build.errors import DockerBuildEnvironmentError
from utilities.docker_build.images import ensure_base_images, is_registry_failure
from utilities.file_io import UnsafeRepoFile, read_repo_file

_MAX_MANIFEST_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class DependencyPlan:
    language: str
    base_image: str
    tag: str
    manifests: tuple[str, ...]
    install_command: str
    workdir: str
    prompt_note: str
    # Cache identity and build context use the same captured contents.
    inputs: tuple[tuple[str, str], ...] = ()


def _read_input(root: Path, name: str) -> str | None:
    path = root / name
    try:
        inside = path.parent.resolve().is_relative_to(root.resolve())
    except RuntimeError as exc:
        raise ValueError(f"依赖清单目录存在循环链接：{name}") from exc
    if not inside:
        raise ValueError(f"依赖文件超出仓库目录：{name}")
    return read_repo_file(path, max_bytes=_MAX_MANIFEST_BYTES)


def _requirements(root: Path, name: str, contents: dict[str, str]) -> None:
    name = posixpath.normpath(name)
    if name in contents:
        return
    if len(contents) >= 128:
        raise ValueError("依赖清单引用过多，沿用逐条构建")
    text = _read_input(root, name)
    if text is None:
        raise ValueError(f"依赖清单不存在：{name}")
    contents[name] = text
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?:-r|-c|--requirement(?:=|\s)|--constraint(?:=|\s))\s*(.+)$", line)
        if match:
            values = shlex.split(match[1], comments=True)
            if len(values) != 1:
                raise ValueError(f"无法读取依赖清单引用：{name}")
            child = (Path(name).parent / values[0]).as_posix()
            _requirements(root, child, contents)
        elif (line.startswith(("-e", "--editable", ".", "/"))
              or re.search(r"(?:^|\s)file:|@\s*[./]", line)
              or (line.startswith("--find-links") and "http" not in line)):
            raise ValueError("本地项目依赖需要完整源码，沿用逐条构建")


def _prefer_cached(candidates: list[str], available: tuple[str, ...]) -> str:
    # OS variants may share a version; a cached newer runtime must not replace
    # the declared vulnerable runtime.
    return next((item for item in candidates if item in available), candidates[0])


def _dockerfile(plan: DependencyPlan) -> str:
    env = ""
    toolchain = ""
    if plan.language == "node":
        env = "ENV NODE_PATH=/app/node_modules\n"
        toolchain = ("RUN apt-get update \\\n"
                     " && apt-get install -y --no-install-recommends python3 make g++ \\\n"
                     " && rm -rf /var/lib/apt/lists/*\n")
    elif plan.language == "go":
        env = "ENV GOMODCACHE=/go/pkg/mod GOTOOLCHAIN=local\n"
    copies = "".join("COPY " + json.dumps([name, "./" + name]) + "\n"
                     for name in plan.manifests)
    return (f"FROM {plan.base_image}\n{toolchain}WORKDIR {plan.workdir}\n"
            f"{env}{copies}RUN {plan.install_command}\n")


def _plan(language: str, base: str, contents: dict[str, str], install: str,
          note: str, workdir: str = "/app") -> DependencyPlan:
    plan = DependencyPlan(language, base, "", tuple(contents), install,
                          workdir, note, tuple(sorted(contents.items())))
    digest = hashlib.sha256(_dockerfile(plan).encode())
    for name, text in plan.inputs:
        digest.update(name.encode() + b"\0" + text.encode() + b"\0")
    return replace(plan, tag=f"vulscan/deps-{language}:{digest.hexdigest()[:20]}")


def plan_for_repository(language: str, repo_root: str | None,
                        available: tuple[str, ...] = ()) -> DependencyPlan | None:
    from utilities.dynamic_tester.declared_runtime import derive_declared_runtimes

    if not repo_root or not Path(repo_root).is_dir():
        return None
    root = Path(repo_root)
    lang = (language or "").strip().lower()
    declared = derive_declared_runtimes(root)
    contents: dict[str, str] = {}
    try:
        if lang in ("python", "py"):
            requirement = _read_input(root, "requirements.txt")
            pyproject = _read_input(root, "pyproject.toml")
            if requirement is not None:
                _requirements(root, "requirements.txt", contents)
                filename = "requirements.txt"
            elif pyproject is not None:
                project = tomllib.loads(pyproject).get("project", {})
                if "dependencies" in project.get("dynamic", []):
                    raise ValueError("动态 Python 依赖需要项目源码，沿用逐条构建")
                dependencies = project.get("dependencies")
                if not isinstance(dependencies, list) or not dependencies:
                    return None
                if not all(isinstance(d, str) and "\n" not in d and "\r" not in d
                           and not re.search(r"file:|@\s*[./]", d)
                           for d in dependencies):
                    raise ValueError("Python 依赖清单包含本地路径或无效依赖")
                contents["pyproject.toml"] = pyproject
                filename = "vulscan-requirements.txt"
                contents[filename] = "\n".join(dependencies) + "\n"
            else:
                return None
            if not declared.get("python") and (
                    _read_input(root, ".python-version") is not None
                    or (pyproject is not None and
                        tomllib.loads(pyproject).get("project", {}).get("requires-python"))):
                raise ValueError("无法确定 Python 版本约束，沿用逐条构建")
            version = declared.get("python", "3.12")
            base = _prefer_cached([f"python:{version}-slim-bookworm",
                                   f"python:{version}-slim"], available)
            return _plan("python", base, contents,
                         f"python -m pip install --no-cache-dir --timeout 15 --retries 1 -r {filename}",
                         "第三方依赖已装在系统 site-packages。仍需 COPY 真实应用源码；"
                         "可以在构建时安装应用本身或补充测试所需依赖，不要重复安装相同依赖。")
        if lang in ("javascript", "js", "typescript", "ts", "node"):
            for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
                text = _read_input(root, name)
                if text is not None:
                    contents[name] = text
            if "package.json" not in contents:
                return None
            package = json.loads(contents["package.json"])
            scripts = package.get("scripts") or {}
            if package.get("workspaces") or any(k in scripts for k in (
                    "preinstall", "install", "postinstall", "prepare", "prepublish")):
                raise ValueError("工作区或项目安装脚本需要应用源码，沿用逐条构建")
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                if any(str(v).startswith(("file:", "link:", "workspace:", ".", "/"))
                       for v in (package.get(group) or {}).values()):
                    raise ValueError("Node 本地依赖需要应用源码，沿用逐条构建")
            if (package.get("engines") or {}).get("node") and not declared.get("node"):
                raise ValueError("无法确定 Node 版本约束，沿用逐条构建")
            version = declared.get("node", "24")
            base = _prefer_cached([f"node:{version}-slim", f"node:{version}-bookworm-slim"], available)
            locked = "package-lock.json" in contents or "npm-shrinkwrap.json" in contents
            return _plan("node", base, contents,
                         "npm " + ("ci" if locked else "install") + " --no-audit --no-fund",
                         "依赖保存在 /app/node_modules，NODE_PATH 已设置。使用 /app 作为工作目录，"
                         "将真实源码复制到 /app/repository，保留父目录依赖；只补充测试所需的额外依赖。")
        if lang in ("go", "golang"):
            for name in ("go.mod", "go.sum"):
                text = _read_input(root, name)
                if text is not None:
                    contents[name] = text
            if "go.mod" not in contents:
                return None
            if re.search(r"=>\s*(?:\.{1,2}/|/)", contents["go.mod"]):
                raise ValueError("Go 本地模块替换需要应用源码，沿用逐条构建")
            if re.search(r"(?m)^\s*(?:go|toolchain)\s", contents["go.mod"]) and not declared.get("go"):
                raise ValueError("无法确定 Go 版本约束，沿用逐条构建")
            version = declared.get("go", "1.26")
            base = _prefer_cached([f"golang:{version}-alpine", f"golang:{version}"], available)
            return _plan("go", base, contents, "go mod download",
                         "依赖已下载到 /go/pkg/mod，GOTOOLCHAIN=local。保留目标 go.mod/go.sum，"
                         "不要在已有模块内再次 go mod init。复制真实项目后在构建阶段编译；"
                         "运行时不下载、不编译。", "/src")
    except (OSError, UnsafeRepoFile, ValueError, TypeError, AttributeError) as exc:
        print(f"  依赖缓存未启用：{exc}", file=sys.stderr)
    return None


def _image_present(tag: str, runner) -> bool:
    out, _err, code, timed = runner(
        ["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=60)
    return code == 0 and not timed and bool(out.strip())


def ensure_dependency_image(plan: DependencyPlan, repo_root: str, runner,
                            proxy_arguments=(), build_timeout: int = 900,
                            pull_timeout: int = 600) -> str | None:
    if _image_present(plan.tag, runner):
        return plan.tag
    from core import ui_events
    ui_events.emit("activity", stage="dynamic-test", phase="environment", status="running",
                   message="准备共享依赖镜像", details=plan.tag)
    ensure_base_images([plan.base_image], runner, timeout=pull_timeout)
    context = tempfile.mkdtemp(prefix="vulscan-deps-")
    try:
        for name, text in plan.inputs:
            path = Path(context) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        dockerfile = Path(context) / "Dockerfile"
        dockerfile.write_text(_dockerfile(plan), encoding="utf-8")
        argv = ["docker", "build", "--builder", "default", "-t", plan.tag,
                "--label", "io.vulscan.dependencies=1", *proxy_arguments,
                "-f", str(dockerfile), context]
        out, err, code, timed = runner(argv, timeout=build_timeout,
                                      on_output=ui_events.command_output("build"))
        if code == 0 and not timed:
            print(f"  依赖镜像已就绪：{plan.tag}", file=sys.stderr)
            ui_events.emit("activity", stage="dynamic-test", phase="environment", status="success",
                           message="共享依赖镜像已就绪", details=plan.tag)
            return plan.tag
        diagnostic = "\n".join(part for part in (out, err) if part).strip()
        if timed or is_registry_failure(diagnostic) or "no space left on device" in diagnostic.lower():
            raise DockerBuildEnvironmentError(
                f"依赖镜像准备失败（{'构建超时' if timed else '构建环境错误'}）：{diagnostic[-2000:]}")
        print(f"  依赖镜像构建失败，沿用逐条安装：{diagnostic[-2000:]}", file=sys.stderr)
        return None
    finally:
        shutil.rmtree(context, ignore_errors=True)
