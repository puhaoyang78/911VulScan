"""基础镜像：Dockerfile 解析、本机清单、按需拉取与注册表故障识别。"""

from pathlib import Path

import pytest

from utilities.docker_build import (
    IMAGE,
    DockerBuildEnvironmentError,
    available_images,
    dockerfile_bases,
    ensure_base_images,
    is_registry_failure,
)
from utilities.dynamic_tester.docker_executor import DockerExecutionResult


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_dockerfile_bases_reads_every_stage_and_skips_scratch(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM --platform=linux/amd64 python:3.12-slim AS build\n")
    _write(tmp_path, "attacker-server/Dockerfile",
           "FROM golang:1.26-alpine\nFROM scratch\nFROM python:3.12-slim\n")
    assert dockerfile_bases(str(tmp_path)) == ("python:3.12-slim", "golang:1.26-alpine")


def test_dockerfile_bases_ignores_variable_interpolation(tmp_path):
    _write(tmp_path, "Dockerfile", "ARG BASE=python:3.12-slim\nFROM ${BASE}\n")
    assert dockerfile_bases(str(tmp_path)) == ()


def test_available_images_hides_untagged_entries():
    def runner(command, **kwargs):
        return "python:3.12-slim\n<none>:<none>\nnode:20-slim\n", "", 0, False
    assert available_images(runner) == ("python:3.12-slim", "node:20-slim")


def test_ensure_base_images_pulls_only_what_is_missing():
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            present = command[-1] == "python:3.12-slim"
            return ("sha256:x" if present else ""), ("" if present else "No such image"), 0 if present else 1, False
        return "", "pulled", 0, False
    result = ensure_base_images(("python:3.12-slim", "golang:1.26-alpine"), runner, timeout=30)
    assert result.cached == ("python:3.12-slim",)
    assert result.pulled == ("golang:1.26-alpine",)
    assert [c for c in calls if c[0] == "docker" and c[1] == "pull"] == [["docker", "pull", "golang:1.26-alpine"]]


def test_ensure_base_images_failure_explains_the_daemon_boundary():
    def runner(command, **kwargs):
        if command[:3] == ["docker", "image", "inspect"]:
            return "", "No such image", 1, False
        return "", "Error response from daemon: dial tcp: i/o timeout", 1, False
    with pytest.raises(DockerBuildEnvironmentError) as excinfo:
        ensure_base_images(("python:3.11-slim",), runner, timeout=10)
    message = str(excinfo.value)
    assert "python:3.11-slim" in message
    assert "守护进程" in message, "必须说明镜像拉取不受构建代理控制"


@pytest.mark.parametrize("text", [
    "failed to resolve source metadata for docker.io/library/python:3.11-slim",
    "failed to fetch anonymous token: dial tcp 31.13.64.7:443: i/o timeout",
    "Get https://registry-1.docker.io/v2/: no such host",
])
def test_registry_failures_are_recognised(text):
    assert is_registry_failure(text) is True


@pytest.mark.parametrize("text", [
    "COPY failed: file not found in build context",
    "E: Unable to locate package gcc",
    "gcc: error: expected declaration",
])
def test_dockerfile_errors_are_not_registry_failures(text):
    assert is_registry_failure(text) is False


def test_image_failure_kind_is_not_retried_and_labelled():
    execution = DockerExecutionResult().fail(IMAGE, "failed to resolve source metadata")
    assert execution.retryable is False
    assert execution.infrastructure_error is True
    assert execution.failure_kind == IMAGE
