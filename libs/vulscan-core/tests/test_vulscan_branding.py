# Modified 2026-10-23 for the VulScan-only product namespace.
"""Public branding, packaging, and configuration use only the new namespace."""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from vulscan.cli import build_parser
from utilities.llm.registry import default_config_path, load_config_file

CORE_ROOT = Path(__file__).resolve().parent.parent


def test_public_parser_brand():
    parser = build_parser()
    assert parser.prog == "vulscan"
    assert "911VulScan" in parser.format_help()


def test_module_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "vulscan", "--help"],
        cwd=CORE_ROOT, capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    assert "usage: vulscan" in proc.stdout
    assert "911VulScan" in proc.stdout


def test_wheel_metadata_has_only_new_entrypoint():
    metadata = tomllib.loads((CORE_ROOT / "pyproject.toml").read_text())
    assert metadata["project"]["name"] == "vulscan"
    assert metadata["project"]["scripts"] == {"vulscan": "vulscan.cli:main"}
    packages = metadata["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert packages.count("vulscan") == 1
    assert "openant" not in packages
    assert not (CORE_ROOT / "openant").exists()


@pytest.mark.parametrize("xdg", [False, True])
def test_new_configuration_isolated_from_old_install(tmp_path, monkeypatch, xdg):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    base = tmp_path / ".config"
    if xdg:
        base = tmp_path / "custom-config"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(base))

    old_path = base / "openant" / "config.json"
    old_path.parent.mkdir(parents=True)
    old_data = json.dumps({"api_key": "test-old-config-key"})
    old_path.write_text(old_data)
    path = base / "vulscan" / "config.json"
    assert default_config_path() == path
    assert load_config_file().default_llm == "deepseek-default"
    assert not path.exists()
    assert old_path.read_text() == old_data

    path.parent.mkdir(parents=True)
    new_data = json.dumps({"api_key": "test-new-config-key"})
    path.write_text(new_data)
    assert load_config_file().default_llm == "vulscan-default"
    assert path.read_text() == new_data
    assert old_path.read_text() == old_data
