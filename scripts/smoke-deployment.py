#!/usr/bin/env python3
# Modified 2026-10-23 for the VulScan-only product namespace.
"""Build and exercise an extracted deployment package without LLM/API calls."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, **kwargs) -> None:
    subprocess.run(args, check=True, **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", action="store_true", help="Also exercise the complete installer (requires dependency network)")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="vulscan-deployment-") as tmp:
        base = Path(tmp)
        archive = base / "source.tar.gz"
        run(sys.executable, str(ROOT / "scripts/package-deployment.py"), "--output", str(archive))
        with tarfile.open(archive) as bundle:
            bundle.extractall(base, filter="data")
        source = base / "911VulScan"
        binary = source / "bin/vulscan"
        binary.parent.mkdir()
        run("go", "build", "-buildvcs=false", "-trimpath", "-o", str(binary), ".", cwd=source / "apps/vulscan-cli")
        run(sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation", str(source / "libs/vulscan-core"), "-w", str(base / "wheels"))
        wheel, = (base / "wheels").glob("*.whl")
        installed = base / "installed"
        run(sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(installed), str(wheel))
        env = dict(os.environ, PYTHONPATH=str(installed), VULSCAN_PYTHON=sys.executable, HOME=str(base / "home"))
        Path(env["HOME"]).mkdir()
        run(sys.executable, "-m", "vulscan", "--help", cwd=base, env=env)
        run(sys.executable, "-c", '''
from pathlib import Path
from core.language_registry import require_registry
from core.model_registry import require_models
import core, vulscan
assert require_registry() and require_models()
root = Path(core.__file__).parent.parent
assert root == Path(vulscan.__file__).parent.parent
assert (root / "config/languages.json").is_file()
assert (root / "config/models.json").is_file()
assert (root / "utilities/autopatcher/prompts/patch_generator.md").is_file()
assert (root / "utilities/dynamic_tester/docker_templates/c.Dockerfile").is_file()
assert not (root / "tests").exists()
assert not (root / "openant").exists()
''', cwd=base, env=env)
        registry = json.loads((installed / "config/languages.json").read_text())
        for spec in registry["languages"].values():
            script = spec["parser"].get("script")
            if script:
                run(sys.executable, str(installed / script), "--help", cwd=base, env=env, stdout=subprocess.DEVNULL)
        run(str(binary), "--help", cwd=base, env=env)
        if args.installer:
            install_env = dict(os.environ, HOME=env["HOME"], PYTHON=sys.executable)
            install_env.pop("PYTHONPATH", None)
            run("sh", str(source / "scripts/install-deployment.sh"), cwd=base, env=install_env)
            run(str(binary), "--help", cwd=base, env=install_env)
            run(str(binary), "version", cwd=base, env=install_env)
            run(str(source / ".venv/bin/python"), "-m", "pip", "check", env=install_env)
            assert not (source / "bin/openant").exists()
            refusal = subprocess.run([str(binary), "uninstall", "--hard"], check=False, cwd=base, env=install_env, capture_output=True, text=True)
            assert refusal.returncode != 0 and "portable" in refusal.stderr.lower()
            assert (source / "bin/vulscan-cli").is_file()
            env = install_env
        # A real local HTTP response verifies embedded UI assets survived packaging.
        with (base / "serve.log").open("w+") as log:
            server = subprocess.Popen([str(binary), "serve", "--addr", "127.0.0.1:0"], cwd=base, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    log.seek(0)
                    output = log.read()
                    match = re.search(r"http://127\.0\.0\.1:\d+", output)
                    if match:
                        with urllib.request.urlopen(match.group(), timeout=5) as response:
                            assert response.status == 200
                            assert "911VulScan" in response.read().decode()
                        # Check exact packaged font/highlighter/theme bytes,
                        # not just an HTML page mentioning their filenames.
                        for name, folder in (("tabler-1.4.0.min.css", "design"),
                                             ("highlight-11.11.1.min.js", "design"),
                                             ("inter-latin-wght-5.2.5.woff2", "design"),
                                             ("jetbrains-mono-latin-400-5.2.5.woff2", "design"),
                                             ("workbench.css", "static"), ("shell.js", "static"), ("scan.js", "static")):
                            with urllib.request.urlopen(match.group() + "/assets/" + name, timeout=5) as asset:
                                assert asset.read() == (source / "apps/vulscan-cli/ui" / folder / name).read_bytes(), name
                        break
                    if server.poll() is not None:
                        raise RuntimeError(output)
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Deployment UI startup timed out: " + output)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
        print("Deployment archive, Go CLI, installed wheel, config/prompt assets and HTTP UI: PASS")


if __name__ == "__main__":
    main()
