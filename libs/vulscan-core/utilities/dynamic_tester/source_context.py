"""Repository files shared by test generation and Docker staging."""

from pathlib import Path
import ast
import shutil

from core.repo_walk import walk_repository


_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", ".aws", ".ssh", ".docker",
    ".codex", ".agents",
}
_PRIVATE_FILES = {".npmrc", ".pypirc", ".netrc", ".git-credentials"}
_MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.cfg", "package.json", "go.mod"}


def repository_files(repo_path: str) -> list[tuple[Path, str]]:
    root = Path(repo_path).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("动态验证的仓库路径必须是目录")
    files = []
    total_size = 0

    def add(path, relative):
        nonlocal total_size
        if path.name in _PRIVATE_FILES or path.name == ".env" or path.name.startswith(".env."):
            return
        total_size += path.stat().st_size
        if len(files) >= 10000 or total_size > 100 * 1024 * 1024:
            raise ValueError("动态验证源码上下文超过 10000 个文件或 100 MiB；请选择项目子目录")
        files.append((path, relative))

    stats = {}
    walk_repository(root, should_exclude_directory=lambda name: name in _EXCLUDED_DIRS,
                    on_file=add, stats=stats)
    if stats.get("directories_unreadable") or stats.get("symlinks_skipped"):
        raise ValueError("动态验证源码上下文存在不可读文件或越界符号链接，无法完整预置")
    return files


def describe_repository(repo_path: str | None) -> dict | None:
    if not repo_path:
        return None
    files = repository_files(repo_path)
    manifests = {}
    module_imports = {}
    for path, relative in files:
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
        shutil.copy2(path, output)
    return (Path("repository") / relative).as_posix()
