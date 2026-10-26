"""可选构建代理：校验、可达性探测，以及本机回环代理的桥接中继。

Docker 构建容器里的 ``127.0.0.1`` 指向容器自身，不是宿主回环；因此填在界面上的
``127.0.0.1:7890`` 必须经过一条受控的桥接中继，否则构建内的 apt/pip/go 会得到
连接被拒绝并回落到极慢的直连。中继只绑定 Docker 默认 bridge 的网关地址，只接受
来自该子网的连接，连接数有上限，构建结束即关闭。
"""

from contextlib import contextmanager
import ipaddress
import http.client
import json
import select
import socket
import socketserver
import threading
from urllib.parse import urlsplit

from utilities.docker_build.errors import DockerBuildEnvironmentError

# 中继端口的候选序列。端口参与 ``--build-arg HTTP_PROXY`` 的值，而 BuildKit 把
# 代理变量算进 RUN 层的缓存键：每次换端口都会让已缓存的依赖安装层失效，构建
# 又要重新下载。二阶段构建由全局构建锁串行化，因此优先复用同一个端口。
_RELAY_PORTS = tuple(range(39901, 39917))

_INSPECT_BRIDGE = ["docker", "network", "inspect", "bridge", "--format", "{{json .IPAM.Config}}"]


def parse_docker_proxy(value: str | None) -> str | None:
    """把界面/命令行输入规范化为 ``http://IP:port``，留空表示不启用。"""
    if not value or not value.strip():
        return None
    try:
        url = urlsplit(value.strip())
        address = ipaddress.ip_address(url.hostname or "")
        if (url.scheme != "http" or url.username is not None or url.password is not None
                or url.path not in {"", "/"} or url.query or url.fragment
                or url.port is None or not 1 <= url.port <= 65535
                or address.is_unspecified or address.is_multicast):
            raise ValueError
        host = f"[{address}]" if address.version == 6 else str(address)
        return f"http://{host}:{url.port}"
    except ValueError:
        raise ValueError("Docker 代理必须使用 http://IP:端口，端口范围为 1–65535") from None


def describe_proxy(proxy: str | None) -> str:
    """日志用的一句话描述；从不回显凭据（本模块不接受凭据）。"""
    return f"构建代理 {proxy}" if proxy else "未启用构建代理（直连）"


def probe_proxy(proxy: str | None, timeout: float = 5.0, *, target: str | None = None) -> None:
    """确认端口；指定依赖源时还验证 CONNECT、TLS 与 HTTP 响应。

    HEAD 不下载索引或安装包，不读取系统绕过规则，也不切换到直连。
    它只验证所需链路可用，不能保证后续大文件下载速度。
    """
    if not proxy:
        return
    url = urlsplit(proxy)
    try:
        if target is None:
            with socket.create_connection((url.hostname, url.port), timeout=timeout):
                return
        endpoint = urlsplit(target)
        connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=timeout)
        try:
            connection.set_tunnel(endpoint.hostname, endpoint.port or 443)
            connection.request("HEAD", endpoint.path or "/", headers={"Connection": "close"})
            response = connection.getresponse()
            if response.status >= 400:
                raise OSError(f"依赖源返回 HTTP {response.status}")
        finally:
            connection.close()
    except (OSError, http.client.HTTPException) as exc:
        raise DockerBuildEnvironmentError(
            f"Docker 构建代理无法连接{('依赖源 ' + target) if target else ''}（{url.hostname}:{url.port}）：{exc}。"
            "请确认代理已启动，或清空代理设置以使用直连。") from exc


class _ProxyRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, upstream, subnet):
        self.upstream = upstream
        self.subnet = subnet
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(32)
        self.connections = set()
        self.connection_lock = threading.Lock()
        super().__init__(address, _RelayHandler)

    def verify_request(self, request, client_address):
        # 只服务 Docker bridge 子网，且同时最多 32 条连接。
        return ipaddress.ip_address(client_address[0]) in self.subnet and self.slots.acquire(False)

    def close_connections(self):
        self.stopping.set()
        with self.connection_lock:
            for connection in list(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # 对端可能已经先关闭。
                connection.close()


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        upstream = None
        try:
            upstream = socket.create_connection(server.upstream, timeout=5)
            peers = [self.request, upstream]
            for connection in peers:
                connection.settimeout(5)
            with server.connection_lock:
                server.connections.update(peers)
            while not server.stopping.is_set():
                ready, _, _ = select.select(peers, [], [], 1)
                for connection in ready:
                    data = connection.recv(65536)
                    if not data:
                        return
                    other = upstream if connection is self.request else self.request
                    other.sendall(data)
        except (OSError, ValueError):
            # 关闭两端连接会把真实的代理/网络故障传递给 apt/pip/npm/go，
            # 绝不会在失败后悄悄切换到直连。
            return
        finally:
            with server.connection_lock:
                server.connections.discard(self.request)
                if upstream is not None:
                    server.connections.discard(upstream)
            if upstream is not None:
                upstream.close()
            server.slots.release()


def _bridge_network(runner):
    out, err, code, timed = runner(_INSPECT_BRIDGE, timeout=15)
    if code or timed:
        raise DockerBuildEnvironmentError(
            "无法确定 Docker 构建网络：" + (err or out or str(code))[:1000])
    networks = json.loads(out)
    config = next((item for item in networks if ":" not in item.get("Gateway", ":")), None)
    if not config:
        raise DockerBuildEnvironmentError("Docker 构建代理需要可用的本机 IPv4 bridge 网络")
    return config["Gateway"], ipaddress.ip_network(config["Subnet"])


def _bind_relay(gateway: str, subnet, upstream) -> _ProxyRelay:
    last_error: OSError | None = None
    for port in (*_RELAY_PORTS, 0):
        try:
            return _ProxyRelay((gateway, port), upstream, subnet)
        except OSError as exc:  # 端口被占用时依次尝试，最后的 0 表示临时端口
            last_error = exc
    raise DockerBuildEnvironmentError(f"无法在 Docker bridge 上启动代理中继：{last_error}")


def _arguments(proxy: str | None) -> list[str]:
    if not proxy:
        return []
    arguments = []
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        arguments.extend(["--build-arg", f"{name}={proxy}"])
    # 宿主继承来的绕过规则会让显式选择的代理悄悄失效。
    for name in ("NO_PROXY", "no_proxy"):
        arguments.extend(["--build-arg", f"{name}="])
    return arguments


@contextmanager
def build_proxy_arguments(value, runner):
    """产出 Docker 构建参数；代理只用于构建，绝不传给测试容器。

    回环代理需要一条范围极窄的 TCP 中继：容器的回环不是宿主的回环。中继不修改
    mihomo、不改 Docker daemon 配置、也不把构建切到 host 网络。
    """
    proxy = parse_docker_proxy(value)
    relay = thread = None
    try:
        if proxy:
            probe_proxy(proxy)
            url = urlsplit(proxy)
            if ipaddress.ip_address(url.hostname).is_loopback:
                gateway, subnet = _bridge_network(runner)
                relay = _bind_relay(gateway, subnet, (url.hostname, url.port))
                thread = threading.Thread(target=relay.serve_forever, daemon=True)
                thread.start()
                proxy = f"http://{relay.server_address[0]}:{relay.server_address[1]}"
        yield _arguments(proxy)
    finally:
        if relay is not None:
            relay.close_connections()
            relay.shutdown()
            relay.server_close()
        if thread is not None:
            thread.join(timeout=5)
