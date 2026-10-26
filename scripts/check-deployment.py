#!/usr/bin/env python3
"""Validate an installed deployment using local parsers and controlled Docker tests."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

SOURCES = {
    "python": {"main.py": "def greet(name):\n    return 'hello ' + name\n"},
    "javascript": {"main.js": "export function greet(name) { return 'hello ' + name; }\n",
                   "typed.ts": "export function add(a: number, b: number): number { return a+b; }\n"},
    "go": {"main.go": "package main\nfunc add(a, b int) int { return a+b }\nfunc main() { add(1,2) }\n"},
    "c": {"main.c": "int add(int a, int b) { return a+b; }\n",
          "extra.cpp": "int subtract(int a, int b) { return a-b; }\n"},
    "ruby": {"main.rb": "def greet(name)\n  'hello ' + name\nend\n"},
    "php": {"main.php": "<?php\nfunction greet($name) { return 'hello ' . $name; }\n"},
    "zig": {"main.zig": "pub fn add(a: i32, b: i32) i32 { return a + b; }\n"},
    "swift": {"main.swift": "func add(_ a: Int, _ b: Int) -> Int { return a + b }\n"},
    "rust": {"main.rs": "pub fn add(a: i32, b: i32) -> i32 { a + b }\n"},
}


def run(label: str, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=kwargs.pop("timeout", 180), **kwargs)
    if result.returncode:
        raise RuntimeError(f"{label}失败（退出码 {result.returncode}）：\n" + (result.stderr + result.stdout)[-6000:])
    return result


def check_parsers(root: Path) -> None:
    registry = json.loads((root / "config/languages.json").read_text())
    with tempfile.TemporaryDirectory(prefix="vulscan-deployment-parsers-") as folder:
        base = Path(folder)
        home = base / "home"
        home.mkdir()
        env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"))
        for language, spec in registry["languages"].items():
            if not spec.get("enabled"):
                continue
            files = SOURCES[language]
            source, output = base / language, base / (language + "-output")
            source.mkdir()
            for filename, text in files.items():
                (source / filename).write_text(text, encoding="utf-8")
            run("Git 分支初始化", ["git", "init", "-b", "main", str(source)], env=env)
            run(language + " 解析", [str(root / "bin/vulscan"), "--json", "parse", str(source),
                                    "--language", language, "--level", "all", "--output", str(output)],
                cwd=base, env=env, timeout=600)
            dataset = json.loads((output / "dataset.json").read_text())
            if not dataset.get("units"):
                raise RuntimeError(language + " 解析没有产生分析对象，部署验证未通过。")
            print(f"解析器 {language}: {len(dataset['units'])} 个分析对象，正常", flush=True)


def check_docker() -> None:
    run("Docker 访问", ["docker", "info"], timeout=30)
    run("Compose 插件", ["docker", "compose", "version"], timeout=30)
    run("Buildx 插件", ["docker", "buildx", "version"], timeout=30)
    name = "vulscan-deployment-" + uuid.uuid4().hex
    image = name + ":check"
    built = False
    compose_started = False
    with tempfile.TemporaryDirectory(prefix="vulscan-deployment-docker-") as folder:
        base = Path(folder)
        (base / "probe.c").write_text("int main(void) { return 0; }\n")
        run("本地测试程序编译", ["cc", "-static", "-O2", "-o", str(base / "probe"), str(base / "probe.c")])
        (base / "Dockerfile").write_text('FROM scratch\nCOPY probe /probe\nRUN ["/probe"]\nENTRYPOINT ["/probe"]\n')
        compose = ["docker", "compose", "-p", name, "-f", str(base / "compose.json")]
        (base / "compose.json").write_text(json.dumps({"services": {"probe": {
            "image": image, "pull_policy": "never", "network_mode": "none", "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "labels": {"org.911vulscan.deployment-check": name},
        }}}))
        try:
            run("Docker 构建", ["docker", "buildx", "build", "--load", "--network=none", "--label",
                               "org.911vulscan.deployment-check=" + name, "-t", image, str(base)])
            built = True
            run("Compose 配置", compose + ["config", "--quiet"])
            compose_started = True
            run("容器执行", compose + ["up", "--abort-on-container-exit", "--exit-code-from", "probe"], timeout=90)
        finally:
            try:
                if compose_started:
                    run("部署测试容器清理", compose + ["down", "--timeout", "5", "--remove-orphans"], timeout=30)
            finally:
                inspect = subprocess.run(["docker", "image", "inspect", image], check=False,
                                         capture_output=True, timeout=20)
                if built or inspect.returncode == 0:
                    run("部署测试镜像清理", ["docker", "image", "rm", image], timeout=30)
    print("Docker 构建、Compose 执行与资源清理：正常", flush=True)


def check_url(url: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 60
    error = "服务尚未响应"
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=3) as response:
                if response.status == 200 and "911VulScan" in response.read().decode("utf-8"):
                    print("网页服务：" + url + "，正常", flush=True)
                    return
                error = "响应不是 911VulScan 页面"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = str(exc)
        time.sleep(0.5)
    raise RuntimeError("网页服务未就绪：" + error)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--docker", action="store_true")
    mode.add_argument("--url")
    args = parser.parse_args()
    root = args.root.resolve()
    os.environ["PATH"] = os.pathsep.join(str(root / ".tools" / tool / "bin") for tool in ("git", "go", "node")) + os.pathsep + os.environ["PATH"]
    if args.url:
        check_url(args.url)
    elif args.docker:
        check_docker()
    else:
        check_parsers(root)


if __name__ == "__main__":
    main()
