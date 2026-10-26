"""依赖镜像：清单识别、内容摘要、按需构建与失败降级。"""

from pathlib import Path

from utilities.docker_build.dependencies import (
    ensure_dependency_image,
    plan_for_repository,
)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_python_plan_uses_requirements_and_content_hash(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    plan = plan_for_repository("Python", str(root))
    assert plan is not None
    assert plan.manifests == ("requirements.txt",)
    assert "pip install" in plan.install_command
    assert plan.workdir == "/app"

    (root / "requirements.txt").write_text("flask\n", encoding="utf-8")
    changed = plan_for_repository("python", str(root))
    assert changed.tag != plan.tag, "清单变了必须换镜像标签"


def test_python_plan_reads_pinned_interpreter(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "flask\n", ".python-version": "3.11.9\n"})
    assert plan_for_repository("python", str(root)).base_image.startswith("python:3.11")


def test_node_plan_prefers_npm_ci_when_lock_exists(tmp_path):
    root = _repo(tmp_path, {"package.json": "{}", "package-lock.json": "{}"})
    plan = plan_for_repository("javascript", str(root))
    assert plan.manifests == ("package.json", "package-lock.json")
    assert plan.install_command.startswith("npm ci")
    assert "NODE_PATH" in plan.prompt_note


def test_go_plan_reads_toolchain_version(tmp_path):
    root = _repo(tmp_path, {"go.mod": "module x\n\ngo 1.22.1\n", "go.sum": ""})
    plan = plan_for_repository("go", str(root))
    assert plan.base_image.startswith("golang:1.22")
    assert plan.install_command == "go mod download"


def test_unsupported_or_manifestless_repos_have_no_plan(tmp_path):
    empty = _repo(tmp_path, {"README.md": "hi"})
    assert plan_for_repository("python", str(empty)) is None
    assert plan_for_repository("c", str(empty)) is None
    assert plan_for_repository("python", None) is None


def test_existing_image_skips_build(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "flask\n"})
    plan = plan_for_repository("python", str(root))
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return "sha256:abc", "", 0, False

    assert ensure_dependency_image(plan, str(root), runner) == plan.tag
    assert all("build" not in argv for argv in calls)


def test_build_uses_manifests_and_proxy_args(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "flask\n"})
    plan = plan_for_repository("python", str(root))
    seen = {}

    def runner(argv, **kwargs):
        if argv[1] == "image":
            return "", "no image", 1, False
        seen["argv"] = argv
        dockerfile = Path(argv[argv.index("-f") + 1]).read_text(encoding="utf-8")
        seen["dockerfile"] = dockerfile
        return "", "", 0, False

    tag = ensure_dependency_image(plan, str(root), runner,
                                  proxy_arguments=("--build-arg", "HTTP_PROXY=http://10.0.0.1:8080"))
    assert tag == plan.tag
    assert seen["dockerfile"].startswith(f"FROM {plan.base_image}")
    assert "requirements.txt" in seen["dockerfile"]
    assert "HTTP_PROXY=http://10.0.0.1:8080" in seen["argv"]


def test_build_failure_degrades_without_raising(tmp_path):
    root = _repo(tmp_path, {"requirements.txt": "flask\n"})
    plan = plan_for_repository("python", str(root))

    def runner(argv, **kwargs):
        if argv[1] == "image":
            return "", "no image", 1, False
        return "", "ERROR: no space left on device", 1, False

    assert ensure_dependency_image(plan, str(root), runner) is None
