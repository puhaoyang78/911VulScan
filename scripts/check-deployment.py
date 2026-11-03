#!/usr/bin/env python3
"""Validate an installed deployment using local parsers and controlled Docker tests."""
from __future__ import annotations

import argparse
import errno
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


def check_port(port: int, *, automatic: bool = False) -> int:
    if not 1024 <= port <= 65535:
        raise ValueError("部署端口必须在 1024–65535 之间。")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as exc:
            if automatic and exc.errno == errno.EADDRINUSE:
                listener.bind(("127.0.0.1", 0))
            else:
                raise RuntimeError(f"端口 {port} 无法使用：{exc}；请用 --port 指定空闲端口，现有服务未停止。") from exc
        return listener.getsockname()[1]


def check_url(url: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 60
    error = "服务尚未响应"
    while time.monotonic() < deadline:
        try:
            with opener.open(urllib.request.Request(url, headers={"Accept": "text/html"}), timeout=3) as response:
                if response.status == 200 and "911VulScan" in response.read().decode("utf-8"):
                    print("网页服务：" + url + "，正常", flush=True)
                    return
                error = "响应不是 911VulScan 页面"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = str(exc)
        time.sleep(0.5)
    raise RuntimeError("网页服务未就绪：" + error)


def check_idle(url: str, service_home: Path | None = None) -> None:
    # New services keep the global queue private. Deployment runs as the service
    # account, so only it can read this local operator credential. Old services
    # without the file retain their original live-page check during upgrades.
    token_path = (service_home or Path.home()) / ".vulscan/webui/.access/operator-token"
    if token_path.exists():
        token = token_path.read_text().strip()
        if len(token) != 64:
            raise RuntimeError("部署凭据无效，未停止服务。")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(url.rstrip("/") + "/internal/status", headers={"Authorization": "Bearer " + token})
        with opener.open(request, timeout=5) as response:
            state = json.loads(response.read(65536))
        if state.get("application") != "911VulScan" or type(state.get("running")) is not int or state["running"] < 0:
            raise RuntimeError("无法确认现有服务的活动任务，未停止服务或更新程序。")
        if state["running"]:
            raise RuntimeError("仍有运行、排队或取消中的扫描，请等待任务结束后重新部署；现有服务与扫描未改变。")
        print("现有服务没有活动扫描，可以更新。", flush=True)
        return
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


def service_listeners(root: Path, pid: int, uid: int, proc: Path) -> tuple[str, set[str]]:
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
    sockets = set()
    for entry in (process / "fd").iterdir():
        try:
            sockets.add(os.readlink(entry))
        except FileNotFoundError:
            continue  # A different request can close a descriptor during inspection.
    listeners = [line.split() for line in (process / "net/tcp").read_text().splitlines()[1:]]
    return expected, {row[1] for row in listeners if row[3] == "0A" and f"socket:[{row[9]}]" in sockets}


def service_url(root: Path, pid: int, uid: int, proc: Path = Path("/proc")) -> str:
    _, listeners = service_listeners(root, pid, uid, proc)
    # Discover only a unique listener owned by the verified application process.
    # This also recovers older services that silently changed their loopback port.
    urls = set()
    for local in listeners:
        address, port = local.split(":")
        host = socket.inet_ntoa(bytes.fromhex(address)[::-1])
        if host == "0.0.0.0":
            host = "127.0.0.1"
        if host.startswith("127."):
            urls.add(f"http://{host}:{int(port, 16)}")
    if len(urls) != 1:
        raise RuntimeError("无法确认服务唯一的网页监听地址，未停止现有服务。")
    return urls.pop()


def check_service(root: Path, pid: int, uid: int, url: str, proc: Path = Path("/proc")) -> None:
    expected, listeners = service_listeners(root, pid, uid, proc)
    parsed = urllib.parse.urlsplit(url)
    address = socket.inet_aton(parsed.hostname)[::-1].hex().upper()
    local_addrs = {f"{address}:{parsed.port:04X}", f"00000000:{parsed.port:04X}"}
    if not listeners & local_addrs:
        raise RuntimeError("网页端口不属于 systemd 服务进程，可能被旧服务占用。")
    print(f"实际运行程序：PID={pid} UID={uid} SHA-256={expected}，与安装程序一致。", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--docker", action="store_true")
    mode.add_argument("--url")
    mode.add_argument("--idle-url")
    mode.add_argument("--listen-port", type=int)
    mode.add_argument("--select-port", type=int)
    mode.add_argument("--service-url", action="store_true")
    parser.add_argument("--service-pid", type=int)
    parser.add_argument("--service-uid", type=int)
    args = parser.parse_args()
    root = args.root.resolve()
    os.environ["PATH"] = os.pathsep.join(str(root / ".tools" / tool / "bin") for tool in ("git", "go", "node")) + os.pathsep + os.environ["PATH"]
    if args.service_url:
        if args.service_pid is None or args.service_uid is None:
            parser.error("--service-url requires --service-pid and --service-uid")
        print(service_url(root, args.service_pid, args.service_uid), flush=True)
    elif args.select_port is not None:
        print(check_port(args.select_port, automatic=True), flush=True)
    elif args.listen_port is not None:
        print(f"部署端口：127.0.0.1:{check_port(args.listen_port)}，可用。", flush=True)
    elif args.url:
        check_url(args.url)
        if args.service_pid is not None:
            if args.service_uid is None:
                parser.error("--service-pid requires --service-uid")
            check_service(root, args.service_pid, args.service_uid, args.url)
    elif args.idle_url:
        service_home = None
        if args.service_pid is not None:
            if args.service_uid is None:
                parser.error("--service-pid requires --service-uid")
            check_service(root, args.service_pid, args.service_uid, args.idle_url)
            environment = (Path("/proc") / str(args.service_pid) / "environ").read_bytes().split(b"\0")
            homes = [entry[5:].decode() for entry in environment if entry.startswith(b"HOME=")]
            if len(homes) != 1 or not Path(homes[0]).is_absolute():
                raise RuntimeError("无法确认服务主目录，未停止服务。")
            service_home = Path(homes[0])
        check_idle(args.idle_url, service_home)
    elif args.docker:
        check_docker()
    else:
        check_parsers(root)


if __name__ == "__main__":
    main()
