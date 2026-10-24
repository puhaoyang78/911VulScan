import json
import socket
import socketserver
import threading
from urllib.parse import urlsplit

import pytest

from utilities.docker_build import build_proxy_arguments, parse_docker_proxy


@pytest.mark.parametrize("value, expected", [
    (None, None), ("", None), ("  ", None),
    ("http://127.0.0.1:7890", "http://127.0.0.1:7890"),
    (" http://192.168.1.2:8080/ ", "http://192.168.1.2:8080"),
    ("http://[::1]:7890", "http://[::1]:7890"),
])
def test_proxy_validation(value, expected):
    assert parse_docker_proxy(value) == expected


@pytest.mark.parametrize("value", ["http://localhost:7890", "socks5://127.0.0.1:7890",
    "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://user:pass@127.0.0.1:7890",
    "http://127.0.0.1:7890/path", "http://0.0.0.0:7890", "http://127.0.0.1:7890?x=1"])
def test_invalid_proxy_rejected(value):
    with pytest.raises(ValueError):
        parse_docker_proxy(value)


def test_blank_proxy_needs_no_network_or_docker():
    def unexpected(*args, **kwargs):
        pytest.fail("blank proxy must not inspect Docker")
    with build_proxy_arguments(None, unexpected) as arguments:
        assert arguments == []


def test_loopback_proxy_relay_transports_bytes_and_closes():
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(1024)
            if data:
                self.request.sendall(data)

    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return json.dumps([{"Gateway": "127.0.0.1", "Subnet": "127.0.0.0/8"}]), "", 0, False
    try:
        with build_proxy_arguments(f"http://127.0.0.1:{upstream.server_address[1]}", runner) as arguments:
            values = dict(arguments[i + 1].split("=", 1) for i in range(0, len(arguments), 2))
            url = urlsplit(values["HTTP_PROXY"])
            endpoint = (url.hostname, url.port)
            assert values["HTTPS_PROXY"] == values["http_proxy"] == values["HTTP_PROXY"]
            assert values["NO_PROXY"] == ""
            with socket.create_connection(endpoint, timeout=2) as connection:
                connection.sendall(b"real relay data")
                assert connection.recv(1024) == b"real relay data"
        with pytest.raises(OSError):
            socket.create_connection(endpoint, timeout=1)
        assert calls[0][:4] == ["docker", "network", "inspect", "bridge"]
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_relay_port_is_stable_so_build_cache_survives():
    """The relay port is part of the build-arg value, hence part of BuildKit's
    cache key for every RUN layer. A random port would invalidate the cached
    dependency install on every finding."""
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(1024)
            if data:
                self.request.sendall(data)

    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()

    def runner(command, **kwargs):
        return json.dumps([{"Gateway": "127.0.0.1", "Subnet": "127.0.0.0/8"}]), "", 0, False

    def observed_port() -> int:
        with build_proxy_arguments(
                f"http://127.0.0.1:{upstream.server_address[1]}", runner) as arguments:
            values = dict(arguments[i + 1].split("=", 1) for i in range(0, len(arguments), 2))
            return urlsplit(values["HTTP_PROXY"]).port

    try:
        assert observed_port() == observed_port()
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)
