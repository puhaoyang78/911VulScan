# Modified 2026-10-23 for the VulScan-only product namespace.
"""Python、JS/TS、Go harness 回归；本地执行只使用本测试创建的受控源码。

不调用模型、不安装依赖、不扫描外部项目。Docker 模板检查不能代替真实容器集成。
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from utilities.dynamic_tester import should_skip_for_language
from utilities.dynamic_tester import test_generator as generator


CORE = Path(__file__).resolve().parents[1]
TEMPLATES = CORE / "utilities" / "dynamic_tester" / "docker_templates"


@pytest.mark.parametrize("filename,template,section", [
    ("target.py", "python", "Python 导入与依赖规则"),
    ("target.js", "node", "JavaScript / TypeScript 构建规则"),
    ("target.cjs", "node", "JavaScript / TypeScript 构建规则"),
    ("target.mjs", "node", "JavaScript / TypeScript 构建规则"),
    ("target.ts", "node", "JavaScript / TypeScript 构建规则"),
    ("target.go", "go", "Go 编译与模块规则"),
])
def test_per_finding_guidance_beats_scan_language(filename, template, section):
    prompt = generator._build_finding_prompt(
        {"location": {"file": filename}}, {"language": "c"})
    assert generator.resolve_docker_template(filename, "c") == template
    assert should_skip_for_language(filename, "c") == (False, "")
    assert section in prompt
    assert "C/C++ 固定编译运行模板" not in prompt
    assert (TEMPLATES / f"{template}.Dockerfile").read_text(encoding="utf-8") in prompt
    assert "仅目标单个源文件" in prompt
    assert "harness 文件名必须与目标源文件" in prompt



def test_python_template_accepts_no_dependencies_and_copies_target():
    template = (TEMPLATES / "python.Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim" in template
    assert "COPY . ." in template
    assert "if [ -f requirements.txt ]" in template
    assert "python -m pip install --no-cache-dir -r requirements.txt" in template
    assert "PYTHONDONTWRITEBYTECODE=1" in template
    assert "PYTHONUNBUFFERED=1" in template
    assert 'CMD ["python", "test_exploit.py"]' in template


def test_node_template_installs_compiler_dependencies_only_at_build():
    template = (TEMPLATES / "node.Dockerfile").read_text(encoding="utf-8")
    assert "npm install --include=dev --no-audit --no-fund" in template
    assert "--production" not in template
    assert "COPY . ." in template
    assert 'CMD ["node", "test_exploit.cjs"]' in template
    guidance = generator._managed_guidance("node")
    for term in (".cjs", ".mjs", "devDependencies", "./node_modules/.bin/tsc", "NodeNext", "完整扩展名"):
        assert term in guidance


def test_go_template_builds_module_and_binary_without_masking_errors():
    template = (TEMPLATES / "go.Dockerfile").read_text(encoding="utf-8")
    assert "FROM golang:1.26-alpine" in template
    assert "GOTOOLCHAIN=local" in template
    assert "GOCACHE=/opt/vulscan-go-build-cache" in template
    assert "GOMODCACHE=/go/pkg/mod" in template
    assert "RUN go mod init vulscan-test && go mod tidy" in template
    assert "RUN go build -mod=readonly -o /test/test_exploit ." in template
    assert "|| true" not in template
    assert 'CMD ["./test_exploit"]' in template
    assert "GOMODCACHE=/tmp" not in generator.SYSTEM_PROMPT
    for term in ("package main", "vulscan-test/target", "*_test.go", "go test -c", "-require=", "CGO"):
        assert term in generator._managed_guidance("go")


@pytest.mark.parametrize("retry", [False, True])
def test_language_guidance_survives_generation_and_retry(monkeypatch, retry):
    seen = []
    generated = {"dockerfile": "FROM node:24-slim", "test_script": "console.log('{}')", "test_filename": "test.cjs"}

    def fake_text(binding, prompt, **kwargs):
        seen.append(prompt)
        return json.dumps(generated)

    monkeypatch.setattr(generator, "simple_text", fake_text)
    finding, repo = {"location": {"file": "target.ts"}}, {"language": "c"}
    if retry:
        result = generator.regenerate_test(finding, repo, generated, "Cannot find module './target.js'", None)
        assert "Cannot find module './target.js'" in seen[0]
        assert "without changing the target or inventing successful evidence" in seen[0]
    else:
        result = generator.generate_test(finding, repo, None)
    assert result == generated
    assert "JavaScript / TypeScript 构建规则" in seen[0]
    assert "./node_modules/.bin/tsc" in seen[0]


def _run(command, cwd, *, env=None):
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", timeout=120, check=False)


def _fixture_files(tmp_path):
    root = tmp_path / "allowed"
    root.mkdir()
    (root / "public.txt").write_text("PUBLIC", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("VULSCAN_PRIVATE_MARKER", encoding="utf-8")
    return root


def _assert_result(completed, variant):
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    expected = "CONFIRMED" if variant == "vulnerable" else "NOT_REPRODUCED"
    assert result["status"] == expected
    assert result["details"] == "读取结果核验"
    assert bool(result["evidence"]) == (variant == "vulnerable")
    if result["evidence"]:
        assert result["evidence"][0]["content"] == "VULSCAN_PRIVATE_MARKER"


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_real_python_explicit_source_import(tmp_path, variant):
    root = _fixture_files(tmp_path)
    # A hyphenated filename cannot be imported as an ordinary Python identifier.
    target = tmp_path / "reviewed-target.py"
    guard = '    if candidate.parent != root.resolve():\n        raise ValueError("拒绝越界路径")\n' if variant == "fixed" else ""
    target.write_text('from pathlib import Path\ndef read_target(root, requested):\n'
                      '    root = Path(root)\n    candidate = (root / requested).resolve()\n'
                      + guard + '    return candidate.read_text(encoding="utf-8")\n', encoding="utf-8")
    harness = tmp_path / "test_exploit.py"
    harness.write_text('import importlib.util, json, sys\n'
                       'spec = importlib.util.spec_from_file_location("reviewed_target", "reviewed-target.py")\n'
                       'target = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(target)\n'
                       'try:\n    content = target.read_target(sys.argv[1], "../secret.txt")\n'
                       'except ValueError:\n    content = ""\n'
                       'leaked = content == "VULSCAN_PRIVATE_MARKER"\n'
                       'print(json.dumps({"status": "CONFIRMED" if leaked else "NOT_REPRODUCED", '
                       '"details": "读取结果核验", "evidence": [{"type": "file_read", "content": content}] if leaked else []}, ensure_ascii=False))\n', encoding="utf-8")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    _assert_result(_run([sys.executable, str(harness), str(root)], tmp_path, env=env), variant)
    assert not (tmp_path / "__pycache__").exists()


@pytest.mark.parametrize("module_mode,suffix", [("commonjs", ".cjs"), ("module", ".mjs")])
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_real_javascript_module_modes(tmp_path, module_mode, suffix, variant):
    node = shutil.which("node")
    if not node:
        pytest.skip("缺少 Node.js，未执行真实 JS fixture")
    root = _fixture_files(tmp_path)
    # Extension semantics must remain explicit even when package.json says the opposite.
    (tmp_path / "package.json").write_text(json.dumps({"type": "module" if module_mode == "commonjs" else "commonjs"}))
    imports = ('const fs = require("node:fs"); const path = require("node:path");\n' if module_mode == "commonjs"
               else 'import fs from "node:fs"; import path from "node:path";\n')
    guard = 'if (path.dirname(candidate) !== path.resolve(root)) throw new Error("拒绝越界路径");' if variant == "fixed" else ""
    function = 'function readTarget(root, requested) { const candidate = path.resolve(root, requested); ' + guard + ' return fs.readFileSync(candidate, "utf8"); }\n'
    export = 'module.exports = { readTarget };\n' if module_mode == "commonjs" else 'export { readTarget };\n'
    (tmp_path / f"target{suffix}").write_text(imports + function + export, encoding="utf-8")
    load = f'const {{readTarget}} = require("./target{suffix}");\n' if module_mode == "commonjs" else f'import {{readTarget}} from "./target{suffix}";\n'
    harness = tmp_path / f"test_exploit{suffix}"
    harness.write_text(load + 'let content = ""; try { content = readTarget(process.argv[2], "../secret.txt"); } catch {}\n'
                       'const leaked = content === "VULSCAN_PRIVATE_MARKER";\n'
                       'console.log(JSON.stringify({status: leaked ? "CONFIRMED" : "NOT_REPRODUCED", details: "读取结果核验", '
                       'evidence: leaked ? [{type:"file_read", content}] : []}));\n', encoding="utf-8")
    _assert_result(_run([node, str(harness), str(root)], tmp_path), variant)


def test_real_typescript_compiles_before_node_runs(tmp_path):
    node = shutil.which("node")
    tsc = CORE / "parsers" / "javascript" / "node_modules" / "typescript" / "bin" / "tsc"
    if not node or not tsc.is_file():
        pytest.skip("缺少已安装 TypeScript 编译器，未下载依赖")
    (tmp_path / "package.json").write_text('{"type":"commonjs"}', encoding="utf-8")
    # enum needs real compilation, not just deleting type annotations.
    (tmp_path / "target.ts").write_text('export enum Decision { Denied, Allowed }\n'
                                        'export function allow(input: string): Decision { return input === "safe" ? Decision.Allowed : Decision.Denied; }\n')
    (tmp_path / "test_exploit.ts").write_text('import { allow, Decision } from "./target.js";\n'
                                              'if (allow("unsafe") !== Decision.Denied) throw new Error("fixture failure");\n'
                                              'console.log(JSON.stringify({status:"NOT_REPRODUCED", details:"类型脚本编译后运行", evidence:[]}));\n')
    compiled = _run([node, str(tsc), "--module", "commonjs", "--target", "ES2020", "--outDir", "dist",
                     "target.ts", "test_exploit.ts"], tmp_path)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    completed = _run([node, "dist/test_exploit.js"], tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "NOT_REPRODUCED"


@pytest.fixture(scope="module")
def go_toolchain(tmp_path_factory):
    go = shutil.which("go")
    if not go or not _run([go, "version"], CORE).stdout.startswith("go version go"):
        pytest.skip("缺少真实 Go 编译器，未安装工具链")
    cache = tmp_path_factory.mktemp("managed-go-cache")
    # The controlled fixture has no Git provenance; ignore any ancestor workspace metadata.
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOENV="off", GOWORK="off", GOFLAGS="-buildvcs=false",
               GOCACHE=str(cache / "build"), GOMODCACHE=str(cache / "modules"))
    return go, env


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
@pytest.mark.parametrize("package_mode", ["main", "target"])
def test_real_go_builds_actual_main_or_library_target(tmp_path, go_toolchain, variant, package_mode):
    go, env = go_toolchain
    root = _fixture_files(tmp_path)
    guard = 'if filepath.Dir(candidate) != root { return "", fmt.Errorf("拒绝越界路径") }; ' if variant == "fixed" else ""
    fmt_import = '; "fmt"' if variant == "fixed" else ""
    staged_source = tmp_path / "source.go"
    staged_source.write_text(f'package {package_mode}\nimport ("os"; "path/filepath"{fmt_import})\n'
                                           'func ReadTarget(root, requested string) (string, error) { candidate := filepath.Join(root, requested); '
                                           + guard + 'data, err := os.ReadFile(candidate); return string(data), err }\n', encoding="utf-8")
    if package_mode == "target":
        # Exactly the documented COPY . . -> mkdir/mv layout, without a root duplicate.
        original_bytes = staged_source.read_bytes()
        (tmp_path / "target").mkdir()
        staged_source.rename(tmp_path / "target" / "source.go")
        assert not staged_source.exists()
        assert (tmp_path / "target" / "source.go").read_bytes() == original_bytes
    target_import = '; "vulscan-test/target"' if package_mode == "target" else ""
    call = "target.ReadTarget" if package_mode == "target" else "ReadTarget"
    (tmp_path / "test_exploit.go").write_text('package main\nimport ("encoding/json"; "os"' + target_import + ')\n'
        'func main() { content, _ := ' + call + '(os.Args[1], "../secret.txt"); leaked := content == "VULSCAN_PRIVATE_MARKER"; '
        'status := "NOT_REPRODUCED"; evidence := []map[string]string{}; if leaked { status = "CONFIRMED"; '
        'evidence = append(evidence, map[string]string{"type":"file_read", "content":content}) }; '
        'json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"status":status, "details":"读取结果核验", "evidence":evidence}) }\n', encoding="utf-8")
    for args in (["mod", "init", "vulscan-test"], ["mod", "tidy"], ["build", "-mod=readonly", "-o", "test_exploit", "."]):
        built = _run([go, *args], tmp_path, env=env)
        assert built.returncode == 0, built.stdout + built.stderr
    _assert_result(_run([str(tmp_path / "test_exploit"), str(root)], tmp_path, env=env), variant)


@pytest.mark.parametrize("package_mode", ["main", "target"])
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_real_go_same_package_test_harness(tmp_path, go_toolchain, package_mode, variant):
    """未导出函数/已有 main 使用预编译 test binary，保留源码且只输出一个 JSON。"""
    go, env = go_toolchain
    root = _fixture_files(tmp_path)
    package_dir = tmp_path / "target"
    package_dir.mkdir()
    guard = 'if filepath.Dir(candidate) != root { return "" }; ' if variant == "fixed" else ""
    existing_main = '\nfunc main() { panic("应用 main 不应作为测试入口运行") }\n' if package_mode == "main" else ""
    staged_source = tmp_path / "source.go"
    staged_source.write_text(f'package {package_mode}\nimport ("os"; "path/filepath")\n'
                             'func readTarget(root, requested string) string { candidate := filepath.Join(root, requested); '
                             + guard + 'data, _ := os.ReadFile(candidate); return string(data) }\n' + existing_main, encoding="utf-8")
    staged_source.rename(package_dir / "source.go")
    (package_dir / "exploit_test.go").write_text(f'package {package_mode}\nimport ("encoding/json"; "os"; "testing")\n'
        'var observed string\nfunc TestExploit(t *testing.T) { observed = readTarget(os.Getenv("FIXTURE_ROOT"), "../secret.txt") }\n'
        'func TestMain(m *testing.M) { original := os.Stdout; os.Stdout = os.Stderr; code := m.Run(); os.Stdout = original; '
        'status := "NOT_REPRODUCED"; evidence := []map[string]string{}; if observed == "VULSCAN_PRIVATE_MARKER" { status = "CONFIRMED"; '
        'evidence = append(evidence, map[string]string{"type":"file_read", "content":observed}) }; '
        'if code != 0 { status = "ERROR" }; json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"status":status, '
        '"details":"读取结果核验", "evidence":evidence}); os.Exit(code) }\n', encoding="utf-8")
    for args in (["mod", "init", "vulscan-test"], ["mod", "tidy"], ["test", "-c", "-o", "test_exploit", "./target"]):
        built = _run([go, *args], tmp_path, env=env)
        assert built.returncode == 0, built.stdout + built.stderr
    completed = _run([str(tmp_path / "test_exploit")], tmp_path, env=dict(env, FIXTURE_ROOT=str(root)))
    _assert_result(completed, variant)
    assert "PASS" in completed.stderr


@pytest.mark.parametrize("language", ["python", "node"])
def test_real_missing_import_is_setup_error_not_confirmation(tmp_path, language):
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    if language == "python":
        command = [sys.executable, "-c", "import vulscan_deliberately_missing_fixture_module"]
    else:
        node = shutil.which("node")
        if not node:
            pytest.skip("缺少 Node.js，未执行真实导入失败验证")
        command = [node, "-e", 'require("./vulscan_deliberately_missing_fixture_module.cjs")']
    completed = _run(command, tmp_path)
    assert completed.returncode != 0
    execution = DockerExecutionResult()
    execution.exit_code, execution.stdout, execution.stderr = completed.returncode, completed.stdout, completed.stderr
    result = collect_result({"id": "controlled-import-failure"}, {}, execution)
    assert result.status == "ERROR"
    diagnostic = "No module named" if language == "python" else "Cannot find module"
    assert diagnostic in result.details
