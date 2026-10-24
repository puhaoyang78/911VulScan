import json
from pathlib import Path

import pytest

from utilities.dynamic_tester.docker_executor import _write_test_files, _staged_artifacts
from utilities.dynamic_tester.source_context import describe_repository, stage_repository
from utilities.dynamic_tester.test_generator import _build_finding_prompt
from utilities.dynamic_tester.docker_templates import c_runner


def test_staging_preserves_headers_modules_manifests_and_target_bytes(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "include").mkdir()
    target = repo / "src" / "target.c"
    target.write_text('#include "../include/types.h"\nint inspect(void) { return ANSWER; }\n')
    (repo / "include" / "types.h").write_text('#define ANSWER 42\n')
    (repo / "package.json").write_text('{"type":"module"}')
    (repo / "go.mod").write_text('module example.org/target\n')
    (repo / "helper.py").write_text('ANSWER = 42\n')
    (repo / ".env").write_text('PRIVATE_TOKEN=must-not-leave-host')
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text('private remote')
    work = tmp_path / "work"
    work.mkdir()
    generation = {"native_language": "c", "test_script": '#include "repository/src/target.c"\n'}
    _write_test_files(str(work), generation, str(target), str(repo))
    assert (work / "repository/src/target.c").read_bytes() == target.read_bytes()
    assert (work / "repository/include/types.h").is_file()
    assert (work / "repository/helper.py").is_file()
    assert (work / "repository/package.json").read_bytes() == (repo / "package.json").read_bytes()
    assert not (work / "repository/.env").exists()
    assert not (work / "repository/.git").exists()
    spec = json.loads((work / "_vulscan_c_spec.json").read_text())
    assert spec["target_filename"] == "repository/src/target.c"
    receipt = _staged_artifacts(str(work), str(target))
    assert all(not a["filename"].startswith("repository/") for a in receipt["artifacts"])
    info = describe_repository(str(repo))
    prompt = _build_finding_prompt({"location": {"file": "src/target.c"}}, {"language": "c", "source_context": info})
    assert "repository/src/target.c" in prompt
    assert "example.org/target" in prompt


def test_repository_escape_is_rejected_without_copying_host_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text('pass\n')
    secret = tmp_path / "private.py"
    secret.write_text('PRIVATE = True\n')
    (repo / "leak.py").symlink_to(secret)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ValueError, match="符号链接"):
        stage_repository(str(work), str(repo), str(target))
    assert not (work / "repository/leak.py").exists()


def test_generated_manifest_does_not_overwrite_original(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text('pass\n')
    (repo / "requirements.txt").write_text('Flask==3.1.2\n')
    work = tmp_path / "work"
    work.mkdir()
    _write_test_files(str(work), {"dockerfile": "FROM python:3.11-slim", "test_script": "pass",
        "test_filename": "test.py", "requirements": "requests==2.32.5", "requirements_filename": "requirements.txt"},
        str(target), str(repo))
    assert (work / "repository/requirements.txt").read_text() == 'Flask==3.1.2\n'
    assert (work / "requirements.txt").read_text() == 'requests==2.32.5'


@pytest.mark.parametrize("language,suffix", [("c", ".c"), ("cpp", ".cpp")])
def test_native_runner_compiles_original_repository_header_layout(tmp_path, language, suffix):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "include").mkdir()
    target = repo / "src" / ("target" + suffix)
    target.write_text('#include "../include/value.h"\nint value(void) { return VALUE; }\n')
    (repo / "include/value.h").write_text('#define VALUE 42\n')
    work = tmp_path / "work"
    work.mkdir()
    test = '#include <stdio.h>\n#include "repository/src/target' + suffix + '"\nint main(void) { if(value()!=42) return 1; puts("{\\"status\\":\\"NOT_REPRODUCED\\",\\"details\\":\\"headers available\\",\\"evidence\\":[]}"); return 0; }\n'
    _write_test_files(str(work), {"native_language": language, "test_script": test}, str(target), str(repo))
    result = c_runner.run_test(work / ("test_exploit" + suffix), language,
                               target_filename="repository/src/target" + suffix)
    assert result["status"] == "NOT_REPRODUCED", result
    assert target.read_text().startswith('#include "../include/value.h"')


def test_missing_target_dependency_is_explicitly_not_model_repairable(tmp_path):
    target = tmp_path / "target.c"
    target.write_text('#include "unavailable_library.h"\nint value(void) { return 42; }\n')
    test = tmp_path / "test.c"
    test.write_text('#include "target.c"\nint main(void) { return value(); }\n')
    result = c_runner.run_test(test, "c", target_filename="target.c")
    assert result["status"] == "ERROR"
    assert result["retryable"] is False
    assert "unavailable_library.h" in result["evidence"][0]["content"]
