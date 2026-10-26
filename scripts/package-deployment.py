#!/usr/bin/env python3
# Modified 2026-10-23 for the VulScan-only product namespace.
"""Build a deterministic source-deployment archive, without developer artifacts."""
from __future__ import annotations

import argparse
import gzip
import io
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = "libs/vulscan-core/"
CLI = "apps/vulscan-cli/"
PACKAGES = {"vulscan", "core", "utilities", "parsers", "prompts", "context", "report"}


def included(name: str) -> bool:
    p = Path(name)
    if any(part in {".git", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules", "tests", "testdata", "test_output", "test_data"} for part in p.parts):
        return False
    if p.name.endswith("_test.go") or p.name == "conftest.py":
        return False
    if name in {"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "README.deploy.md", "config/languages.json", "config/models.json", "scripts/install-deployment.sh", "scripts/check-deployment.py"}:
        return True
    if name.startswith(CLI):
        rel = name[len(CLI):]
        return (rel in {"go.mod", "go.sum", "Makefile"}
                or p.suffix == ".go"
                or (rel.startswith(("ui/", "internal/report/templates/", "internal/report/vendor/"))
                    and p.suffix in {".html", ".gohtml", ".js", ".css", ".txt", ".woff2"}))
    if name.startswith(CORE):
        rel = name[len(CORE):]
        if rel in {"pyproject.toml", "requirements.txt", "README.md"}:
            return True
        if Path(rel).parts[0] not in PACKAGES or rel.startswith("utilities/autopatcher/tools/"):
            return False
        if p.suffix == ".md":
            return rel.startswith("utilities/autopatcher/prompts/") or rel in {"context/VULSCAN_TEMPLATE.md", "context/VULSCAN_THREATMODEL_TEMPLATE.md"}
        return p.suffix in {".py", ".js", ".json", ".go", ".mod", ".sum", ".txt", ".Dockerfile"}
    return False


def selected(root: Path) -> list[Path]:
    # Tracked inputs only: never sweep developer scratch files or node_modules.
    names = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0"))
    # Newly introduced product files are explicit until the first commit.
    names.update({"README.deploy.md", "THIRD_PARTY_NOTICES.md", "scripts/install-deployment.sh", "scripts/check-deployment.py",
                  CORE + "vulscan/__init__.py", CORE + "vulscan/__main__.py",
                  CORE + "core/ui_events.py", CLI + "internal/server/events.go",
                  CLI + "internal/report/templates/document.gohtml"})
    # These are curated production asset directories referenced by Go embed;
    # include new resource files before a commit without sweeping scratch dirs.
    for directory in (CLI + "ui/design", CLI + "ui/static"):
        names.update(p.relative_to(root).as_posix() for p in (root / directory).glob("*") if p.is_file())
    paths = sorted(root / name for name in names if name and included(name) and (root / name).is_file())
    required = ["LICENSE", "THIRD_PARTY_NOTICES.md", "README.deploy.md", "config/languages.json", "config/models.json", CLI + "main.go", CORE + "pyproject.toml", CORE + "README.md", CORE + "vulscan/__main__.py", "scripts/install-deployment.sh", "scripts/check-deployment.py"]
    names = {p.relative_to(root).as_posix() for p in paths}
    for name in required:
        if name not in names:
            raise ValueError(f"Missing deployment input: {name}")
    for p in paths:
        if p.is_symlink():
            raise ValueError(f"Symlink is not a deployment input: {p}")
    return paths


def package(root: Path, output: Path) -> int:
    paths = selected(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped, tarfile.open(fileobj=zipped, mode="w|") as archive:
        for path in paths:
            info = tarfile.TarInfo("911VulScan/" + path.relative_to(root).as_posix())
            data = path.read_bytes()
            info.size = len(data)
            info.mode = 0o755 if path.suffix == ".sh" else 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return len(paths)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/911VulScan-source.tar.gz")
    args = parser.parse_args()
    print(f"Packaged {package(ROOT, args.output)} files: {args.output}")
