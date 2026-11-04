"""Repository files shared by test generation and Docker staging."""

from pathlib import Path
import ast
import errno
import os
import shutil

from core.repo_walk import walk_repository


_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", ".aws", ".ssh", ".docker",
    ".codex", ".agents",
}
_PRIVATE_FILES = {".npmrc", ".pypirc", ".netrc", ".git-credentials"}
_MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.cfg", "package.json", "go.mod"}


def _private(path: Path) -> bool:
    return (any(part in _EXCLUDED_DIRS for part in path.parts)
            or path.name in _PRIVATE_FILES or path.name == ".env" or path.name.startswith(".env."))


def _link_target(path: Path, root: Path) -> str:
    """Validate destinations without reading linked contents; cycles and dangling links are valid fixtures."""
    value = os.readlink(path)
    target = Path(os.path.abspath(path.parent / value))
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"动态验证源码准备失败：符号链接 {path.relative_to(root)} 指向仓库之外") from exc
    if _private(relative):
        raise ValueError(f"动态验证源码准备失败：符号链接 {path.relative_to(root)} 指向已排除的配置或凭据路径")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, OSError) and exc.errno != errno.ELOOP:
            raise ValueError(f"动态验证源码准备失败：无法检查符号链接 {path.relative_to(root)}：{exc}") from exc
        resolved = target  # Cycles are preserved, never followed while staging.
    if not resolved.is_relative_to(root) or _private(resolved.relative_to(root)):
        raise ValueError(f"动态验证源码准备失败：符号链接 {path.relative_to(root)} 经其他链接指向仓库之外或已排除路径")
    # An absolute host-repository path would break in the container. Keep its
    # within-repository relationship; relative fixture targets stay byte-for-byte.
    return os.path.relpath(resolved, path.parent) if os.path.isabs(value) else value


def repository_files(repo_path: str) -> list[tuple[Path, str]]:
    root = Path(repo_path).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("动态验证的仓库路径必须是目录")
    files = []
    total_size = 0

    def add(path, relative):
        nonlocal total_size
        if _private(Path(relative)):
            return
        total_size += path.lstat().st_size
        if len(files) >= 10000 or total_size > 100 * 1024 * 1024:
            raise ValueError("动态验证源码上下文超过 10000 个文件或 100 MiB；请选择项目子目录")
        files.append((path, relative))

    def add_link(path, relative):
        if _private(Path(relative)):
            return
        _link_target(path, root)
        add(path, relative)

    stats = {}
    walk_repository(root, should_exclude_directory=lambda name: name in _EXCLUDED_DIRS,
                    on_file=add, on_symlink=add_link, stats=stats)
    if stats.get("directories_unreadable") or stats.get("symlinks_skipped"):
        examples = stats.get("unreadable_examples") or stats.get("symlink_examples") or []
        detail = "; ".join(str(v).replace(str(root) + os.sep, "") for v in examples[:5])
        raise ValueError("动态验证源码准备失败，无法读取仓库文件：" + (detail or "路径未记录"))
    return files


def describe_repository(repo_path: str | None) -> dict | None:
    if not repo_path:
        return None
    files = repository_files(repo_path)
    manifests = {}
    module_imports = {}
    for path, relative in files:
        if path.is_symlink():
            continue  # Preserve link metadata for Docker; never read through it on the host.
        if relative in _MANIFESTS:
            if path.stat().st_size > 12000:
                raise ValueError(f"依赖清单过大，无法提供完整构建上下文：{relative}")
            manifests[relative] = path.read_text(encoding="utf-8")
        if path.suffix == ".py" and len(module_imports) < 160 and path.stat().st_size <= 128000:
            try:
                tree = ast.parse(path.read_bytes())
            except (SyntaxError, UnicodeError):
                continue  # Not parseable as Python 3; never guess dependencies.
            imports = set()
            for item in ast.walk(tree):
                if isinstance(item, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in item.names)
                elif isinstance(item, ast.ImportFrom) and item.level == 0 and item.module:
                    imports.add(item.module.split(".")[0])
            if imports:
                module_imports[relative] = sorted(imports)
    return {"files": [relative for _, relative in files[:160]],
            "file_count": len(files), "manifests": manifests,
            "module_imports": module_imports}


def stage_repository(work_dir: str, repo_path: str, source_file: str) -> str:
    root = Path(repo_path).resolve(strict=True)
    target = Path(source_file).resolve(strict=True)
    relative = target.relative_to(root)
    files = repository_files(str(root))
    if relative.as_posix() not in {name for _, name in files}:
        raise ValueError("目标源文件不在可预置的仓库上下文中")
    destination = Path(work_dir) / "repository"
    destination.mkdir()
    for path, name in files:
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            output.symlink_to(_link_target(path, root))
        else:
            shutil.copy2(path, output, follow_symlinks=False)
    return (Path("repository") / relative).as_posix()
