"""Offline declaration coverage for Python, Node and Go dynamic-test inputs.

These are metadata tests: no Python/npm/Go process, image pull, model
request or static-parser support is implied by a declared runtime.
"""

import json

import pytest

from utilities.dynamic_tester.declared_runtime import (
    _clean_version,
    derive_declared_runtimes,
)


@pytest.mark.parametrize("engine, expected", [
    ("20", "20"),
    ("20.11.1", "20.11.1"),
    ("v20.11.1", "20.11.1"),
    ("= 20.11.1", "20.11.1"),
    ("^20.9.0", "20.9.0"),
    ("~20.11.0", "20.11.0"),
    ("20.x", "20"),
    ("20.*", "20"),
    ("20.x.x", "20"),
    ("20.11.X", "20.11"),
    (">=18", "18"),
    (">=18 <21", "18"),
    (">=20.11.1 <=20.11.1", "20.11.1"),
    (">=20 <=20.1", "20.0.0"),
    (">=20.1 <=20", "20.1"),
    (">=20 <20.1", "20.0.0"),
    (">=20.1 <20.1.9", "20.1.0"),
    ("  >= 20.11.1   < 22  ", "20.11.1"),
])
def test_node_exact_and_simple_ranges(tmp_path, engine, expected):
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": engine}}))
    assert derive_declared_runtimes(str(tmp_path)) == {"node": expected}


@pytest.mark.parametrize("engine", [
    "", "*", ">20", "<22", ">=22 <20", ">=20 <20", ">=20.1 <=20.0",
    "18 || >=20", ">=18 || >=20", "20 - 22", "^20.x", "20.1.x.x",
    ">=20; RUN evil", ">=20.1.2.3", ">=20beta", "RUN >=20", "^20 && evil",
    "２０", ">=" + "9" * 33, ">=20 <" + "9" * 33,
    None, 20, [">=20"], {"version": "20"},
])
def test_node_ambiguous_or_corrupted_engines_are_omitted(tmp_path, engine):
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": engine}}))
    assert derive_declared_runtimes(str(tmp_path)) == {}


def test_standard_asdf_nodejs_name_and_legacy_alias(tmp_path):
    path = tmp_path / ".tool-versions"
    path.write_text("nodejs 20.11.1\nnode 18.20.0\n")
    assert derive_declared_runtimes(str(tmp_path)) == {"node": "20.11.1"}
    path.write_text("node 18.20.0\n")
    assert derive_declared_runtimes(str(tmp_path)) == {"node": "18.20.0"}


@pytest.mark.parametrize("manifest, expected", [
    ("go 1.22\ntoolchain go1.23.4\n", "1.23.4"),
    ("toolchain go1.23.4\ngo 1.22\n", "1.23.4"),
    ("go 1.24\ntoolchain go1.24.0\n", "1.24.0"),
    ("go 1.24\ntoolchain go1.23.4\n", "1.24"),
    ("go 1.24 // floor\ntoolchain go1.24.2 // chosen compiler\n", "1.24.2"),
    ("go 1.24\ntoolchain default\n", "1.24"),
    ("toolchain go1.24.2\n", "1.24.2"),
    ("go 1.24\ntoolchain go1.25rc1\n", "1.24"),
    ("go 1.24\ntoolchain go1.25.0; RUN evil\n", "1.24"),
    ("// toolchain go1.25.0\ngo 1.24\n", "1.24"),
])
def test_go_toolchain_and_minimum_version(tmp_path, manifest, expected):
    (tmp_path / "go.mod").write_text(manifest)
    assert derive_declared_runtimes(str(tmp_path)) == {"go": expected}


@pytest.mark.parametrize("manifest", [
    "go go1.24\n", "toolchain 1.24\n", "toolchain go1.24.1.2\n",
    "toolchain go1.24 && RUN evil\n", "go １.２４\n", "go " + "9" * 33 + "\n",
])
def test_go_invalid_directives_are_omitted(tmp_path, manifest):
    (tmp_path / "go.mod").write_text(manifest)
    assert derive_declared_runtimes(str(tmp_path)) == {}


def test_numeric_version_grammar_is_ascii_and_bounded(tmp_path):
    assert _clean_version("３.１１") is None
    assert _clean_version("21\nRUN evil") is None
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nrequires-python = ">=' + "9" * 33 + '"\n')
    assert derive_declared_runtimes(str(tmp_path)) == {}


@pytest.mark.parametrize("requirement, expected", [
    (">=3.11", "3.11"),
    (">=3.11.9", "3.11.9"),
    (">=3.8, <4", "3.8"),
    ("<4, >=3.11", "3.11"),
    (">=3.8, >=3.11, <4", "3.11"),
    (">=3.11, >=3.8, <4", "3.11"),
    (">=3.11.9, <=3.11.9", "3.11.9"),
    (">=3.11, <=3.11", "3.11.0"),
    (">=3.11, <3.11.9", "3.11.0"),
    (">=3.11, <3.12", "3.11"),
    ("==3.11.9", "3.11.9"),
    ("==3.11", "3.11.0"),
    ("==3", "3.0.0"),
    ("== 3.11.*", "3.11"),
    ("~=3.11", "3.11"),
    ("~=3.11.9", "3.11.9"),
    ("  >= 3.11 , < 4  ", "3.11"),
])
def test_python_exact_compatible_and_strongest_floor(tmp_path, requirement, expected):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nrequires-python = " + json.dumps(requirement) + "\n")
    assert derive_declared_runtimes(str(tmp_path)) == {"python": expected}


@pytest.mark.parametrize("requirement", [
    "", "3.11", "<4", "<=3.12", "~=3", ">3.11", ">=3.11rc1", ">=3.11.1.2",
    ">=3.11evil", "RUN >=3.11", ">=3.11; RUN evil", ">=3.11, RUN evil",
    ">=3.11,", ">=3.11 || >=3.12", ">=3.11 <4", ">=3.11,!=3.11.0",
    ">=3.12,<3.11", ">=3.11,<3.11", ">=3.11.1,<=3.11.0",
    ">=３.１１", "==3.11.*.2", "==3.11; RUN evil", "~=" + "9" * 33 + ".1",
])
def test_python_invalid_or_unsupported_ranges_are_omitted(tmp_path, requirement):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nrequires-python = " + json.dumps(requirement) + "\n")
    assert derive_declared_runtimes(str(tmp_path)) == {}


@pytest.mark.parametrize("content", [
    "[project\n", "project = 3\n", "[project]\nrequires-python = 311\n",
    '[project]\nrequires-python = [">=3.11"]\n',
])
def test_python_malformed_toml_and_non_string_values_degrade(tmp_path, content):
    (tmp_path / "pyproject.toml").write_text(content)
    assert derive_declared_runtimes(str(tmp_path)) == {}


def test_python_explicit_interpreter_precedes_compatibility_floor(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nrequires-python = ">=3.11"\n')
    (tmp_path / ".python-version").write_text("3.12.5\n")
    (tmp_path / ".tool-versions").write_text("python 3.13.1\n")
    assert derive_declared_runtimes(str(tmp_path)) == {"python": "3.12.5"}
    (tmp_path / ".python-version").unlink()
    assert derive_declared_runtimes(str(tmp_path)) == {"python": "3.11"}
    (tmp_path / ".python-version").write_text("3.12.5\n")
    pyproject.write_text('[project]\nrequires-python = ">=3.11evil"\n')
    assert derive_declared_runtimes(str(tmp_path)) == {"python": "3.12.5"}
    (tmp_path / ".python-version").unlink()
    assert derive_declared_runtimes(str(tmp_path)) == {"python": "3.13.1"}


def test_python_deeply_nested_toml_degrades_instead_of_raising(tmp_path):
    (tmp_path / "pyproject.toml").write_text("value = " + "[" * 10000)
    assert derive_declared_runtimes(str(tmp_path)) == {}


@pytest.mark.parametrize("filename", ["pyproject.toml", ".python-version", "package.json", "go.mod"])
def test_manifest_read_limits_and_symlink_refusal(tmp_path, filename):
    path = tmp_path / filename
    path.write_text("x" * 65_537)
    assert derive_declared_runtimes(str(tmp_path)) == {}
    path.unlink()
    target = tmp_path / "other"
    target.write_text("3.11")
    path.symlink_to(target)
    assert derive_declared_runtimes(str(tmp_path)) == {}


