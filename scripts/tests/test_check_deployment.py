"""Real HTTP/proc checks; installer command mocks live in test_install_deployment."""
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("check_deployment", Path(__file__).parents[1] / "check-deployment.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class DeploymentCheckTests(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        self.body = '<strong id="stat-running">0</strong>'
        self.operator = None
        self.running = 0
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/internal/status' and fixture.operator is not None:
                    if self.headers.get('Authorization') != 'Bearer ' + fixture.operator:
                        self.send_response(401)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(__import__('json').dumps({'application': '911VulScan', 'running': fixture.running}).encode())
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(fixture.body.encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def test_idle_is_read_from_live_service(self):
        checker.check_idle(self.url, self.home)
        self.body = '<strong id="stat-running">2</strong>'
        with self.assertRaisesRegex(RuntimeError, "仍有运行"):
            checker.check_idle(self.url, self.home)

    def test_unknown_and_duplicate_counts_cannot_authorize_update(self):
        for body in ('', '<strong id="stat-running">—</strong>', self.body * 2):
            self.body = body
            with self.assertRaisesRegex(RuntimeError, "无法确认"):
                checker.check_idle(self.url, self.home)

    def test_authenticated_global_queue_blocks_redeploy(self):
        self.operator = 'a' * 64
        path = self.home / '.vulscan/webui/.access/operator-token'
        path.parent.mkdir(parents=True)
        path.write_text(self.operator)
        self.body = '<title>登录工作台 · 911VulScan</title>'
        checker.check_idle(self.url, self.home)
        self.running = 2
        with self.assertRaisesRegex(RuntimeError, '仍有运行'):
            checker.check_idle(self.url, self.home)
        path.write_text('b' * 64)
        with self.assertRaises(checker.urllib.error.HTTPError):
            checker.check_idle(self.url, self.home)
        path.write_text('bad')
        with self.assertRaisesRegex(RuntimeError, '凭据无效'):
            checker.check_idle(self.url, self.home)

    @unittest.skipUnless(Path("/proc/self/exe").exists(), "Linux /proc verification")
    def test_actual_process_bytes_uid_and_listener_must_match(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bin").mkdir()
            binary = root / "bin/vulscan-cli"
            shutil.copyfile(Path(sys.executable).resolve(), binary)
            checker.check_service(root, os.getpid(), os.getuid(), self.url)
            with self.assertRaisesRegex(RuntimeError, "账号不一致"):
                checker.check_service(root, os.getpid(), os.getuid() + 1, self.url)
            with self.assertRaisesRegex(RuntimeError, "端口不属于"):
                checker.check_service(root, os.getpid(), os.getuid(), "http://127.0.0.1:1")
            binary.write_bytes(b"new program")
            with self.assertRaisesRegex(RuntimeError, "旧程序"):
                checker.check_service(root, os.getpid(), os.getuid(), self.url)


if __name__ == "__main__":
    unittest.main()
