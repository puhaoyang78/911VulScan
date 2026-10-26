#!/usr/bin/env python3
"""Validate an installed deployment using local parsers and controlled Docker tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from html.parser import HTMLParser
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


def check_idle(url: str) -> None:
    # The shipped 2c94b52 workbench already exposes this count. Read the exact
    # field rather than infer running work from saved (possibly stale) files.
    class RunningCount(HTMLParser):
        def __init__(self):
            super().__init__()
            self.reading = False
            self.values = []

        def handle_starttag(self, tag, attrs):
            if dict(attrs).get("id") == "stat-running":
                self.reading = True

        def handle_data(self, data):
            if self.reading:
                self.values.append(data.strip())

        def handle_endtag(self, tag):
            self.reading = False

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=5) as response:
        parser = RunningCount()
        parser.feed(response.read().decode("utf-8"))
    if len(parser.values) != 1 or not parser.values[0].isdigit():
        raise RuntimeError("无法确认现有服务的活动任务，未停止服务或更新程序。")
    if int(parser.values[0]):
        raise RuntimeError("仍有运行、排队或取消中的扫描，请等待任务结束后重新部署；现有服务与扫描未改变。")
    print("现有服务没有活动扫描，可以更新。", flush=True)


def check_service(root: Path, pid: int, uid: int, url: str, proc: Path = Path("/proc")) -> None:
    if pid <= 0:
        raise RuntimeError("systemd 没有报告有效的 MainPID。")
    process = proc / str(pid)
    if process.stat().st_uid != uid:
        raise RuntimeError("运行进程的用户与配置的服务账号不一致。")
    def digest(path):
        value = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
        return value.hexdigest()
    expected = digest(root / "bin/vulscan-cli")
    if digest(process / "exe") != expected:
        raise RuntimeError("运行进程仍是旧程序，部署未通过版本校验。")
    # A service can fall back to a different port when 8080 is occupied. Prove
    # that the HTTP listener belongs to this MainPID, not an unrelated old UI.
    parsed = urllib.parse.urlsplit(url)
    address = socket.inet_aton(parsed.hostname)[::-1].hex().upper()
    local = f"{address}:{parsed.port:04X}"
    sockets = set()
    for entry in (process / "fd").iterdir():
        try:
            sockets.add(os.readlink(entry))
        except FileNotFoundError:
            continue  # A different request can close a descriptor during inspection.
    listeners = [line.split() for line in (process / "net/tcp").read_text().splitlines()[1:]]
    if not any(row[1] == local and row[3] == "0A" and f"socket:[{row[9]}]" in sockets for row in listeners):
        raise RuntimeError("网页端口不属于 systemd 服务进程，可能被旧服务占用。")
    print(f"实际运行程序：PID={pid} UID={uid} SHA-256={expected}，与安装程序一致。", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--docker", action="store_true")
    mode.add_argument("--url")
    mode.add_argument("--idle-url")
    parser.add_argument("--service-pid", type=int)
    parser.add_argument("--service-uid", type=int)
    args = parser.parse_args()
    root = args.root.resolve()
    os.environ["PATH"] = os.pathsep.join(str(root / ".tools" / tool / "bin") for tool in ("git", "go", "node")) + os.pathsep + os.environ["PATH"]
    if args.url:
        check_url(args.url)
        if args.service_pid is not None:
            if args.service_uid is None:
                parser.error("--service-pid requires --service-uid")
            check_service(root, args.service_pid, args.service_uid, args.url)
    elif args.idle_url:
        if args.service_pid is not None:
            if args.service_uid is None:
                parser.error("--service-pid requires --service-uid")
            check_service(root, args.service_pid, args.service_uid, args.idle_url)
        check_idle(args.idle_url)
    elif args.docker:
        check_docker()
    else:
        check_parsers(root)


if __name__ == "__main__":
    main()
