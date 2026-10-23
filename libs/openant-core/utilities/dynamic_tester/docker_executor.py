"""Docker container execution for dynamic exploit tests.

Handles building images, running containers with timeouts,
and collecting stdout/stderr output. All execution is isolated
in Docker containers with no host volume mounts or privileged mode.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import signal
import threading
import tempfile
import time
import uuid
from utilities.file_io import open_utf8
from utilities import docker_resources
from utilities.dynamic_tester.diagnostics import bounded_diagnostic

# Timeouts
DEFAULT_CONTAINER_TIMEOUT = 120   # seconds per container
DEFAULT_BUILD_TIMEOUT = 300       # seconds for docker build

# Path to the bundled attacker server
_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker_templates")
ATTACKER_SERVER_PATH = os.path.join(_TEMPLATES_DIR, "attacker_server.py")


class DockerExecutionResult:
    """Result from running a Docker container."""

    def __init__(self):
        self.stdout: str = ""
        self.stderr: str = ""
        self.exit_code: int = -1
        self.timed_out: bool = False
        self.build_error: str | None = None
        self.execution_error: str | None = None
        self.infrastructure_error: bool = False
        self.elapsed_seconds: float = 0.0
        # Reporting receipt only; never participates in verdict or execution.
        self.reproduction: dict = {}

    @property
    def success(self) -> bool:
        return (self.build_error is None and self.execution_error is None
                and not self.timed_out and self.exit_code == 0)


# Per-service compose keys we KEEP when reconstructing an untrusted compose. This is an
# ALLOWLIST, not a blocklist: every container-runtime attribute that could grant host
# access — privileged, cap_add, pid/ipc/uts/userns:host, security_opt, devices,
# device_cgroup_rules, cgroup_parent, volumes/host binds (incl /var/run/docker.sock),
# network_mode, ports, user, sysctls, group_add, extra_hosts, dns, env_file, extends,
# secrets, configs, … — is DROPPED by omission and replaced with the fixed hardening set
# in `_harden_service`. A blocklist is non-terminating (network_mode was one round's
# miss); an allowlist contains the NEXT unknown key by default.
# An ORDERED tuple (not a set): the reconstruction iterates it to build each service,
# so a set's hash-randomized order would make the emitted compose non-deterministic.
_SVC_ALLOWLIST = (
    "build", "image", "depends_on", "command", "entrypoint",
    "environment", "expose", "working_dir", "healthcheck", "networks",
)


def _refuse_compose(reason: str) -> str:
    """A services-less (comment-only) compose: `docker compose build`/`up` create ZERO
    containers (verified), so the untrusted definition never executes and the finding is
    recorded non-CONFIRMED (fail-closed, no egress). Note `docker compose build` on an
    empty compose exits 0 ("empty compose file") rather than erroring — safety comes from
    "no services => nothing runs", not from a build failure. We do not raise — the
    orchestrator calls run_single_container unwrapped, so a raise would
    abort the whole dynamic-test run instead of just this finding."""
    return f"# openant: {reason}; refusing to run it (fail-closed).\n"


def _safe_build(build):
    """Return a build spec confined to the work_dir, or raise if it escapes it.

    A compose `build.context` of `/`, `..`, or an absolute path would make
    `docker build` read HOST paths into the image. Only `.`/`./<sub>` (no `..`,
    not absolute) is allowed; `build.dockerfile` is confined the same way.
    """
    def _confined(p) -> bool:
        return (isinstance(p, str) and bool(p) and not p.startswith("/")
                and not p.startswith("~")
                and not any(c in p for c in ("\\", ":", "$"))
                and not any(ord(c) < 32 or ord(c) == 127 for c in p)
                and ".." not in p.split("/"))

    if isinstance(build, str):
        if not _confined(build):
            raise ValueError(f"unsafe build context: {build!r}")
        return build
    if isinstance(build, dict):
        ctx = build.get("context", ".")
        if not _confined(ctx):
            raise ValueError(f"unsafe build context: {ctx!r}")
        out = {"context": ctx}
        df = build.get("dockerfile")
        if df is not None:
            if not _confined(df):
                raise ValueError(f"unsafe dockerfile path: {df!r}")
            out["dockerfile"] = df
        args = build.get("args")
        if isinstance(args, (dict, list)):
            out["args"] = args
        return out
    raise ValueError("service has no usable build spec")


def _safe_leaf(name, default: str) -> str:
    """Confine an LLM-supplied staging filename to a bare leaf inside work_dir.

    generation['test_filename'] / ['requirements_filename'] are LLM output
    influenced by the scanned repo. Used raw as `os.path.join(work_dir, name)`
    they let a `..`/absolute value escape work_dir and write to the HOST during
    pre-container staging (the compose `build.context` analogue that _safe_build
    already confines). The scaffold is flat by construction — the generation
    schema's examples are plain basenames, Dockerfiles `COPY <basename> .` at
    WORKDIR, and pip needs requirements.txt at the build-context root — so
    basename is strictly correct and strips any traversal.

    Fail-closed WITHOUT raising: an unwrapped raise here would abort the whole
    dynamic-test run (see _refuse_compose), so a hostile value degrades to a
    harmless leaf (COPY mismatch -> NOT_REPRODUCED) rather than a host write.
    A non-str value (JSON allows any type), a dot-segment ('.'/'..' -> a
    directory, not a file), and a name colliding with a fixed staging path
    (Dockerfile / docker-compose.yml / attacker-server) all degrade to `default`
    so nothing downstream raises IsADirectoryError / FileExistsError / TypeError.
    """
    if not isinstance(name, str):
        return default
    # A NUL (or other control char) is a str that survives basename and the
    # reserved check, but open()/os.path.join raise ValueError("embedded null
    # byte") — an unwrapped raise here would abort the whole run (the exact
    # fail-closed contract this helper exists to keep). Reject any name carrying a
    # control character (0x00-0x1f, 0x7f) and degrade to the default leaf.
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name):
        return default
    leaf = os.path.basename(name)
    _RESERVED = {"", ".", "..", "Dockerfile", "docker-compose.yml", "attacker-server"}
    return default if leaf in _RESERVED else leaf


def _harden_service(name: str, svc: dict) -> dict:
    """Reconstruct ONE service from the allowlist + the fixed hardening set (C).

    Runtime-privilege keys are dropped by omission (allowlist). No `user`: the container
    runs as its image default (root) with a writable HOME via the /root tmpfs — dropping
    `user` avoids the read-only-`$HOME` breakage that flips HOME-cache-writing tests to
    ERROR, while cap_drop ALL + no-new-privileges + read_only + the internal-only network
    still prevent privilege escalation and host access.
    """
    out = {k: svc[k] for k in _SVC_ALLOWLIST if k in svc}

    # Attacker capture sidecar: a remote "attacker" image is replaced by the bundled,
    # OpenAnt-owned build context (preserves the prior behaviour).
    img = out.get("image")
    if isinstance(img, str) and "attacker" in img.lower():
        out.pop("image", None)
        out["build"] = "./attacker-server"

    if "build" in out:
        out["build"] = _safe_build(out["build"])
    if "build" not in out and "image" not in out:
        raise ValueError(f"service {name!r} declares neither a safe build nor an image")

    # Service network membership is preserved (from the allowlist) and every declared
    # network is forced `internal: true` at the doc level below, so service-name
    # resolution (test -> attacker:9999) keeps working with no external gateway.

    # (C) fixed per-service hardening — applied uniformly to EVERY service, attacker
    # sidecar included (it keeps captures in memory, so read_only is safe; :9999 > 1024
    # so cap_drop ALL does not break its bind).
    out["read_only"] = True
    out["cap_drop"] = ["ALL"]
    out["security_opt"] = ["no-new-privileges:true"]
    out["pids_limit"] = 256
    out["mem_limit"] = "512m"
    out["cpus"] = 1.0
    # Writable scratch + a writable HOME (=/root, image default user) on the RO rootfs.
    out["tmpfs"] = ["/tmp", "/root"]
    return out


def _sanitize_compose(content: str) -> str:
    """RECONSTRUCT an untrusted LLM/target-influenced docker-compose from an allowlist.

    The compose is UNTRUSTED and is built+run (executed). Rather than blocklist the
    dangerous keys (non-terminating — network_mode was one round's miss, then
    privileged/cap_add/volumes/pid/ipc/security_opt/devices), this DISCARDS the LLM's
    per-service runtime attributes entirely and rebuilds each declared service from a
    fixed allowlist (`_SVC_ALLOWLIST`) + a fixed hardening set (`_harden_service`): no
    privileged, no added caps (cap_drop ALL), no host mounts/volumes, no host namespaces,
    no devices, no host network, no `ports` publish, read-only rootfs, no-new-privileges,
    pids/mem/cpu caps — on an `internal: true` network with no external gateway.

    The SERVICE SET is preserved (test + attacker capture server + any extra service the
    generation legitimately needs, e.g. a DB for a SQLi test), so a multi-service test is
    not silently dropped; each service is reconstructed re-hardened.

    Fails CLOSED (returns a refusing comment-only compose) on unparseable YAML, a build
    context that escapes the work dir, or a service with neither a safe build nor an image.

    RESIDUAL (documented, NOT closed here): build-time `RUN` egress — `docker build`
    still runs the generated Dockerfile's RUN steps with network (an egress-allowlisting
    build proxy is deferred, an accepted residual). This change is RUNTIME sandbox
    hardening that makes the code enforce its stated "no host volume mounts or privileged
    mode" contract.
    """
    try:
        import yaml
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("compose root is not a mapping")
    except Exception:
        return _refuse_compose("docker-compose could not be parsed")

    services_in = data.get("services")
    if not isinstance(services_in, dict) or not services_in:
        return _refuse_compose("docker-compose declares no services")

    if len(services_in) > 8:
        return _refuse_compose("docker-compose exceeds the eight-service resource budget")

    services_out = {}
    try:
        for name, svc in services_in.items():
            if not isinstance(svc, dict):
                raise ValueError(f"service {name!r} is not a mapping")
            services_out[name] = _harden_service(name, svc)
    except Exception as exc:
        return _refuse_compose(f"docker-compose could not be safely reconstructed ({exc})")

    # Rebuild the networks: every DECLARED network is forced `internal: true` with
    # `external`/`name` stripped (an external net attaches services to a pre-existing,
    # egress-capable net by name and ignores `internal`), plus an injected internal
    # `default` so a service that omits `networks:` is still contained. Named top-level
    # `volumes:`/`secrets:`/`configs:`/`version:` are dropped by omission (services can
    # no longer reference them — host-bind `volumes:` were stripped per-service above).
    networks_in = data.get("networks")
    networks_out = {}
    if isinstance(networks_in, dict):
        for net_name, cfg in networks_in.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            cfg = {k: v for k, v in cfg.items() if k not in ("external", "name")}
            cfg["internal"] = True
            networks_out[net_name] = cfg
    networks_out["default"] = {"internal": True}

    out = {"services": services_out, "networks": networks_out}
    return yaml.safe_dump(out, default_flow_style=False, sort_keys=False)


def _write_test_files(work_dir: str, generation: dict, source_file: str | None = None) -> None:
    """Write generated test files into the working directory.

    Args:
        work_dir: Temporary directory used as Docker build context.
        generation: LLM-generated test artifacts (dockerfile, test_script, …).
        source_file: Optional path to the vulnerable source file. When given,
            the file is copied into *work_dir* so the Dockerfile can COPY it
            without the LLM having to guess the path.
    """
    if generation.get("native_language"):
        _write_native_test_files(work_dir, generation, source_file)
        return

    # Validate all flat staging names before writing anything. A harness or
    # dependency manifest must never overwrite the target it is meant to test.
    test_filename = _safe_leaf(generation.get("test_filename"), "test_exploit.py")
    req_filename = (_safe_leaf(generation.get("requirements_filename"), "requirements.txt")
                    if generation.get("requirements") else None)
    source_name = os.path.basename(source_file) if source_file else None
    reserved = {"Dockerfile", "docker-compose.yml", "attacker-server"}
    if source_name and (source_name in reserved or source_name in {test_filename, req_filename}):
        raise ValueError("目标源文件名与测试或依赖文件冲突；请为测试/依赖选择不同文件名")
    if req_filename == test_filename:
        raise ValueError("测试文件与依赖文件同名；请使用不同文件名")

    # Pre-stage the vulnerable source file so `COPY <basename> .` just works.
    if source_file and os.path.isfile(source_file):
        shutil.copy2(source_file, os.path.join(work_dir, os.path.basename(source_file)))

    # str() the content fields as a defense-in-depth belt: generate_test already
    # rejects a non-str content field (test_generator validation), but coercing here
    # too means a non-str value can never raise TypeError in f.write and abort the
    # whole run — it degrades to a garbage build that fails safe (NOT_REPRODUCED).
    # Write Dockerfile
    with open_utf8(os.path.join(work_dir, "Dockerfile"), "w") as f:
        f.write(str(generation["dockerfile"]))

    # Write test script (confine the LLM-supplied name to a leaf inside work_dir)
    test_filename = _safe_leaf(generation.get("test_filename"), "test_exploit.py")
    test_path = os.path.join(work_dir, test_filename)
    os.makedirs(os.path.dirname(test_path), exist_ok=True)
    with open_utf8(test_path, "w") as f:
        f.write(str(generation["test_script"]))

    # Write requirements/dependencies file
    if generation.get("requirements"):
        req_filename = _safe_leaf(generation.get("requirements_filename"), "requirements.txt")
        req_path = os.path.join(work_dir, req_filename)
        os.makedirs(os.path.dirname(req_path), exist_ok=True)
        with open_utf8(req_path, "w") as f:
            f.write(str(generation["requirements"]))

    # Copy attacker server if needed (before docker-compose so it's available)
    if generation.get("needs_attacker_server"):
        attacker_dir = os.path.join(work_dir, "attacker-server")
        os.makedirs(attacker_dir, exist_ok=True)
        shutil.copy2(ATTACKER_SERVER_PATH, os.path.join(attacker_dir, "server.py"))
        # Write attacker Dockerfile
        with open_utf8(os.path.join(attacker_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11-slim\nWORKDIR /app\nCOPY server.py .\n"
                    "EXPOSE 9999\nCMD [\"python\", \"server.py\"]\n")

    # Write docker-compose if multi-service, with sanitization
    if generation.get("docker_compose"):
        compose_content = _sanitize_compose(generation["docker_compose"])
        with open_utf8(os.path.join(work_dir, "docker-compose.yml"), "w") as f:
            f.write(compose_content)


def _write_native_test_files(work_dir: str, generation: dict, source_file: str | None) -> None:
    """固定 C/C++ scaffold；模型不能改写执行器、Dockerfile 或编译命令。"""
    language = generation.get("native_language")
    if language not in {"c", "cpp"}:
        raise ValueError("C/C++ 测试语言配置无效")
    if not source_file or not os.path.isfile(source_file):
        raise ValueError("C/C++ 动态验证缺少真实目标源文件；请提供 --repo-path，未执行测试")
    test_name = "test_exploit.cpp" if language == "cpp" else "test_exploit.c"
    reserved = {test_name, "Dockerfile", "_openant_c_runner.py", "_openant_c_spec.json"}
    if source_file:
        source_name = os.path.basename(source_file)
        if source_name in reserved:
            raise ValueError("目标源文件名与 C/C++ 测试模板冲突，未执行测试")
        shutil.copy2(source_file, os.path.join(work_dir, source_name))
    shutil.copy2(os.path.join(_TEMPLATES_DIR, "c.Dockerfile"), os.path.join(work_dir, "Dockerfile"))
    shutil.copy2(os.path.join(_TEMPLATES_DIR, "c_runner.py"), os.path.join(work_dir, "_openant_c_runner.py"))
    with open_utf8(os.path.join(work_dir, test_name), "w") as handle:
        handle.write(generation["test_script"])
    with open_utf8(os.path.join(work_dir, "_openant_c_spec.json"), "w") as handle:
        json.dump({"language": language, "test_filename": test_name,
                   "target_filename": os.path.basename(source_file)}, handle)


# The env the docker build/run subprocess is ALLOWED to see. `docker compose`
# interpolates a `${VAR}` in an untrusted, LLM-authored compose `build.args` from the
# subprocess env at BUILD time; the generated Dockerfile `RUN` then has open build-time
# network egress (an accepted GHSA-98g5 residual that assumed NO host secret was
# reachable at build time). An ALLOWLIST (not a deny-list) closes the exfil BY
# CONSTRUCTION: a provider secret with any name (ANTHROPIC_API_KEY, GH_PAT,
# AWS_ACCESS_KEY_ID, *_APIKEY, *_PASSPHRASE, *_AUTH, SLACK_WEBHOOK, …) is dropped by
# default because it is not on the list, so no new secret-name convention can leak.
# Docker's own needs are a bounded, well-known set. Tradeoff: any build that needs a
# host secret from ENV at build time fails — a private BASE IMAGE via a cloud
# credential-helper (AWS_* for ecr-login), or a private BUILD DEPENDENCY fetched by a
# RUN step (GITHUB_TOKEN for `go mod download` of a GOPRIVATE module, NPM_TOKEN, a
# credentialed PIP_INDEX_URL, …). Such a generated repro fails to build and is recorded
# as status=ERROR (result_collector.py) — VISIBLE and retried, NOT a silent
# NOT_REPRODUCED, so the static verdict is preserved and only the dynamic confirmation is
# missed (the safe side for a SAST tool). Private base images have a workaround (a prior
# `docker login` writes config.json; DOCKER_CONFIG is allowed); a private build-time
# dependency does not (the RUN-step token cannot be supplied without re-opening the
# build-arg exfil this scrub closes) — an accepted coverage limit. Public base images and
# public dependencies are unaffected.
_ENV_ALLOW_EXACT = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "PWD", "TZ", "HOSTNAME",
    "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE",
    "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
    "COLIMA_HOME", "SSH_AUTH_SOCK",  # ssh:// docker context needs the agent socket (a
                                     # unix-socket PATH, not a secret interpolable into a build-arg)
    # The BOUNDED set of real docker CLI knobs. NOT a `DOCKER_` prefix: that prefix
    # re-admits DOCKER_PASSWORD / DOCKER_AUTH_CONFIG (a GitLab-CI registry-cred var) /
    # DOCKER_TOKEN — the exact secret-by-name leak the allowlist exists to prevent.
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION", "DOCKER_BUILDKIT",
    "DOCKER_DEFAULT_PLATFORM", "DOCKER_CLI_EXPERIMENTAL", "DOCKER_CONTENT_TRUST",
    "BUILDKIT_PROGRESS",
    # Windows essentials so docker.exe resolves on CI runners.
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA",
    "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
})
# Only `LC_*` (locale) stays a prefix — it can never carry a provider secret. The
# docker/compose/buildkit knobs are enumerated exactly above precisely because their
# families ALSO contain credential-bearing names (DOCKER_PASSWORD/DOCKER_AUTH_CONFIG).
_ENV_ALLOW_PREFIXES = ("LC_",)
# Proxy vars may embed the user's OWN proxy credential — that is the user's network
# config (needed to reach the daemon/registry), not a provider API key, and dropping
# it would break builds behind a proxy.
_ENV_ALLOW_SUFFIXES = ("_PROXY", "_proxy")
_ENV_ALLOW_LOWER = frozenset({"no_proxy"})


def _scrubbed_subprocess_env() -> dict:
    """os.environ filtered to a docker-essentials ALLOWLIST for the build/run subprocess.

    Everything not explicitly allowed (every ``*_API_KEY`` / ``*_TOKEN`` / ``*_SECRET``
    / ``*_AUTH`` / ``*_PAT`` / arbitrary secret) is dropped, so no host secret can be
    interpolated into an untrusted compose build-arg and exfiltrated over build-time
    egress — regardless of the secret's name.
    """
    def _allowed(name: str) -> bool:
        up = name.upper()
        return (up in _ENV_ALLOW_EXACT
                or name in _ENV_ALLOW_LOWER
                or any(up.startswith(p) for p in _ENV_ALLOW_PREFIXES)
                or any(name.endswith(s) for s in _ENV_ALLOW_SUFFIXES))

    env = {k: v for k, v in os.environ.items() if _allowed(k)}
    # Legacy builders create unlabelled intermediate containers on interruption.
    # Use the explicitly selected daemon BuildKit backend measured by admission.
    env["DOCKER_BUILDKIT"] = "1"
    return env


def _kill_command_tree(process):
    """Freeze/capture descendants before killing a supervised CLI, on all platforms."""
    import psutil
    stopped = []
    def freeze(proc):
        try:
            proc.suspend()
            stopped.append(proc)
            for child in proc.children():
                freeze(child)
        except psutil.NoSuchProcess:
            pass
    try:
        freeze(psutil.Process(process.pid))
    finally:
        for proc in reversed(stopped):
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(stopped, timeout=5)
        if any(proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE for proc in alive):
            raise RuntimeError("Docker CLI descendants did not terminate")


class UnstoppedProducerError(RuntimeError):
    """The supervisor must not race an unverified orphaned Docker producer."""


MAX_COMMAND_OUTPUT = 256 * 1024  # retained bytes per stream; pipes are continuously drained


def _run_command(cmd: list[str], timeout: int, cwd: str = None) -> tuple[str, str, int, bool]:
    """Drain both pipes with bounded memory; stop CLI process groups on cancellation.

    Killing the CLI does not kill daemon containers: owned-resource cleanup below
    is independently required. Keep the tail so compiler/runtime diagnostics survive.
    """
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]
    def drain(pipe, index):
        try:
            while chunk := pipe.read(8192):
                buffers[index].extend(chunk)
                if len(buffers[index]) > MAX_COMMAND_OUTPUT:
                    del buffers[index][:-MAX_COMMAND_OUTPUT]
                    truncated[index] = True
        finally:
            pipe.close()
    own_session = os.name == "posix" and not os.environ.get("OPENANT_DOCKER_OWNER")
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=cwd, env=_scrubbed_subprocess_env(),
                                   start_new_session=own_session)
    except OSError as exc:
        return "", f"无法启动命令 {cmd[0]}：{exc}", 127, False
    registered_producer = False
    if os.environ.get("OPENANT_DOCKER_OWNER"):
        try:
            docker_resources.register_producer(process.pid)
            registered_producer = True
        except BaseException:
            _kill_command_tree(process)
            process.wait()
            raise
    threads = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    timed_out = False
    def stop():
        try:
            if own_session:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                _kill_command_tree(process)
        except ProcessLookupError:
            pass
        except Exception as exc:
            if registered_producer:
                docker_resources.mark_producer_uncertain(process.pid)
            raise UnstoppedProducerError("Docker CLI termination could not be verified") from exc
        process.wait()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop()
    except BaseException:
        stop()
        raise
    finally:
        # Do not signal a process group after wait() has reaped its leader: its
        # numeric ID may be recycled. Retain recovery evidence on orphaned pipes.
        for thread in threads:
            thread.join(timeout=2)
        if registered_producer and not any(thread.is_alive() for thread in threads):
            docker_resources.unregister_producer(process.pid)
    output = [("[earlier output truncated]\n" if truncated[i] else "") +
              bytes(value).decode("utf-8", errors="replace") for i, value in enumerate(buffers)]
    if any(thread.is_alive() for thread in threads):
        if registered_producer:
            docker_resources.mark_producer_uncertain(process.pid)
        raise UnstoppedProducerError("Docker CLI descendant retained output pipes; manual producer recovery required")
    if timed_out:
        output[1] += "\n命令执行超时"
    return output[0], output[1], -1 if timed_out else process.returncode, timed_out


def _staged_artifacts(work_dir: str, source_file: str | None) -> dict:
    """Snapshot files already staged by the existing harness before cleanup.

    Keep the target's hash/name, not another full copy of repository source.
    Recording failure must never change whether a test executes.
    """
    receipt = {"artifacts": []}
    source_name = os.path.basename(source_file) if source_file else None
    try:
        for root, directories, files in os.walk(work_dir):
            directories.sort()
            for filename in sorted(files):
                path = os.path.join(root, filename)
                relative = os.path.relpath(path, work_dir)
                if os.path.islink(path):
                    continue
                if relative == source_name:
                    with open(path, "rb") as handle:
                        receipt["source"] = {"filename": relative,
                                             "sha256": hashlib.file_digest(handle, "sha256").hexdigest()}
                    continue
                with open_utf8(path) as handle:
                    receipt["artifacts"].append({"filename": relative, "content": handle.read()})
    except (OSError, UnicodeError) as exc:
        receipt["capture_error"] = f"暂存产物记录不完整：{type(exc).__name__}"
    return receipt


def _run_recorded_command(result: DockerExecutionResult, stage: str,
                          cmd: list[str], timeout: int, cwd: str = None):
    """Preserve an existing command's result without changing its behavior."""
    outcome = _run_command(cmd, timeout=timeout, cwd=cwd)
    stdout, stderr, code, timed_out = outcome
    result.reproduction.setdefault("commands", []).append({
        "stage": stage, "argv": list(cmd), "cwd": cwd,
        "exit_code": code, "timed_out": timed_out,
        "stdout": bounded_diagnostic(stdout, 12000),
        "stderr": bounded_diagnostic(stderr, 12000),
    })
    return outcome


def run_single_container(
    generation: dict,
    finding_id: str,
    container_timeout: int = DEFAULT_CONTAINER_TIMEOUT,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
    source_file: str | None = None,
) -> DockerExecutionResult:
    """Build and run a single Docker container for a test.

    Args:
        generation: Test generation output (dockerfile, test_script, etc.)
        finding_id: Finding ID for image naming
        container_timeout: Max seconds for container execution
        build_timeout: Max seconds for docker build

    Returns:
        DockerExecutionResult with stdout/stderr/exit_code
    """
    result = DockerExecutionResult()
    start_time = time.time()

    # Sanitize finding_id for use as Docker image tag.
    # Docker tags must match [a-z0-9][a-z0-9._-]*, so strip anything else.
    # UUID prefix prevents collisions between parallel dynamic-test runs
    # (same finding IDs across scans).
    run_id = uuid.uuid4().hex
    safe_id = re.sub(r"[^a-z0-9-]", "-", finding_id.lower()).strip("-_.")[:48] or "finding"
    image_tag = f"openant-test-{run_id}-{safe_id}"
    network_name = f"openant-net-{run_id}-{safe_id}"

    # Use a deterministic, sanitized work_dir name so docker compose project
    # names (derived from the dir name) are always valid Docker references.
    # We still use mkdtemp for uniqueness but strip any non-alphanumeric chars.
    raw_work_dir = tempfile.mkdtemp(prefix=f"openant-test-{safe_id}-")
    parent = os.path.dirname(raw_work_dir)
    safe_basename = re.sub(r"[^a-z0-9-]", "", os.path.basename(raw_work_dir).lower()).strip("-")
    work_dir = os.path.join(parent, safe_basename)
    if work_dir != raw_work_dir:
        os.rename(raw_work_dir, work_dir)

    registered = False
    cleanup_blocked = False
    infrastructure_phase = True
    try:
        docker_resources.register_run(run_id, work_dir)
        registered = True
        infrastructure_phase = False  # Generated staging errors remain eligible for repair.
        _write_test_files(work_dir, generation, source_file=source_file)
        _label_compose(work_dir, run_id)
        receipt = _staged_artifacts(work_dir, source_file)
        result.reproduction.update(receipt)

        infrastructure_phase = True
        with docker_resources.build_admission(timeout=build_timeout, runner=_run_command):
            docker_resources.bind_run_daemon(run_id, runner=_run_command)
            result = _execute_staged(generation, work_dir, run_id, safe_id, image_tag,
                                     network_name, container_timeout, build_timeout)
        result.reproduction.update(receipt)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, TimeoutError) as exc:
        cleanup_blocked = isinstance(exc, UnstoppedProducerError)
        result.execution_error = f"测试执行准备失败：{exc}"
        result.infrastructure_error = infrastructure_phase or cleanup_blocked
    finally:
        result.elapsed_seconds = time.time() - start_time
        if registered:
            try:
                if cleanup_blocked:
                    raise RuntimeError("Cleanup deferred: an unverified Docker producer may remain alive")
                errors = docker_resources.cleanup_owner(docker_resources.owner_id(), run_id, runner=_run_command)
            except Exception as exc:
                errors = [f"Docker cleanup could not complete: {exc}"]
            result.reproduction["cleanup"] = {"ok": not errors, "errors": errors}
            if errors:
                result.execution_error = (result.execution_error or "") + " Docker 资源清理失败：" + "; ".join(errors)
                result.infrastructure_error = True
        else:
            shutil.rmtree(work_dir, ignore_errors=True)
    return result


def _execute_staged(generation, work_dir, run_id, safe_id, image_tag, network_name, container_timeout, build_timeout):
    if generation.get("docker_compose") and generation.get("needs_attacker_server"):
        # Multi-service: use docker compose with explicit project name
        # (#315: the run_id prefix — the parallel-run collision guard
        # the :408 comment names — now on the project name too)
        result = _run_compose(work_dir, compose_project_name(run_id, safe_id),
                              container_timeout, build_timeout)
    else:
        # Single container: docker build + run
        result = _run_single(work_dir, image_tag, network_name,
                             container_timeout, build_timeout)
    return result


def _run_single(
    work_dir: str,
    image_tag: str,
    network_name: str,
    container_timeout: int,
    build_timeout: int,
) -> DockerExecutionResult:
    """Build and run a single Docker container."""
    result = DockerExecutionResult()

    # Build
    stdout, stderr, code, timed_out = _run_recorded_command(
        result, "build", ["docker", "build", "--builder", "default", "-t", image_tag, *_resource_labels(image_tag), "."],
        timeout=build_timeout,
        cwd=work_dir,
    )
    if code != 0 or timed_out:
        diagnostic = "\n".join(part for part in (stdout, stderr) if part)
        result.build_error = (("Docker 构建超时\n" + diagnostic) if timed_out
                              else diagnostic or f"Docker 构建退出码：{code}")
        result.stdout = stdout
        result.infrastructure_error = code == 127 or "unknown flag" in stderr.lower() or "unknown option" in stderr.lower()
        result.stderr = stderr
        result.timed_out = timed_out
        return result

    # F4 hardening: a single-container test has NO sibling service, so it needs no
    # network at all. `--network none` (loopback only, no gateway/DNS) is strictly
    # stronger and simpler than an --internal network: an executing test derived from
    # untrusted findings cannot exfiltrate at runtime, and in-container client->server
    # tests still work over loopback. (No `docker network create` needed for this path.)
    # RESIDUAL: build-time RUN egress is still open — see _sanitize_compose. Hardening,
    # not a vuln fix. The multi-service path uses an internal compose network instead.
    stdout, stderr, code, timed_out = _run_recorded_command(
        result, "run", [
            "docker", "run",
            "--rm",
            "--name", image_tag,
            *_resource_labels(image_tag),
            "--log-driver", "local",
            "--log-opt", "max-size=10m",
            "--log-opt", "max-file=2",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1",
            "--pids-limit", "256",
            "--cap-drop", "ALL",
            "--read-only",
            "--tmpfs", "/tmp:size=256m",
            "--tmpfs", "/root:size=128m",
            "--security-opt", "no-new-privileges",
            # No --user: the container runs as its image default (root) with a writable
            # HOME via the /root tmpfs above. cap_drop ALL + no-new-privileges + read_only
            # + --network none contain it; a non-root --user on a read-only rootfs would
            # instead move $HOME to an unwritable `/` and flip HOME-cache tests to ERROR.
            image_tag,
        ],
        timeout=container_timeout,
        cwd=work_dir,
    )

    result.stdout = stdout
    result.stderr = stderr
    result.exit_code = code
    result.timed_out = timed_out

    return result


def compose_project_name(run_id: str, safe_id: str) -> str:
    """#315: the compose project name carries the per-run UUID prefix.

    The run_id exists precisely to prevent parallel-run collisions (the
    comment below states it); the image tag and the network name carry it,
    but the project name received only safe_id — identical across runs —
    so `docker compose down` (scoped by -p) reached a concurrent run's
    containers and `up -d` recreated them. Same prefix, all three names.
    """
    return f"openant-{run_id}-{safe_id}"


def _run_compose(
    work_dir: str,
    project_name: str,
    container_timeout: int,
    build_timeout: int,
) -> DockerExecutionResult:
    """Build and run multi-service test via docker compose.

    Uses an explicit project name to ensure image tags are always valid
    Docker references, independent of the temp dir name.
    """
    result = DockerExecutionResult()

    compose_base = ["docker", "compose", "-f", os.path.join(work_dir, "docker-compose.yml"), "-p", project_name]

    try:
        stdout, stderr, code, timed_out = _run_recorded_command(
            result, "build", compose_base + ["build", "--builder", "default"], timeout=build_timeout, cwd=work_dir)
        if code != 0 or timed_out:
            diagnostic = "\n".join(part for part in (stdout, stderr) if part)
            result.build_error = (("Docker Compose 构建超时\n" + diagnostic) if timed_out
                                  else diagnostic or f"Docker Compose 构建退出码：{code}")
            result.stdout, result.stderr = stdout, stderr
            result.infrastructure_error = code == 127 or "unknown flag" in stderr.lower() or "unknown option" in stderr.lower()
            result.timed_out = timed_out
            return result
        stdout, stderr, code, timed_out = _run_recorded_command(
            result, "start", compose_base + ["up", "-d", "--no-build"], timeout=60, cwd=work_dir)
        if code != 0 or timed_out:
            result.execution_error = stderr or stdout or "Docker Compose 启动失败"
            result.infrastructure_error = True
            result.timed_out = timed_out
            return result
        stdout, stderr, code, timed_out = _run_recorded_command(
            result, "observe", compose_base + ["logs", "--no-log-prefix", "-f", "test"],
            timeout=container_timeout, cwd=work_dir)
        result.stdout, result.stderr = stdout, stderr
        result.exit_code, result.timed_out = code, timed_out
    finally:
        # No --rmi: externally referenced images must not be deleted. Per-run
        # built images have owned tags/labels and are removed by cleanup_owner.
        _, error, code, timed_out = _run_recorded_command(
            result, "cleanup", compose_base + ["down", "--volumes", "--remove-orphans"],
            timeout=30, cwd=work_dir)
        if code != 0 or timed_out:
            result.execution_error = (result.execution_error or "") + " Docker Compose 清理失败: " + error
            result.infrastructure_error = True
    return result


def _resource_labels(image_tag):
    match = re.match(r"openant-test-([a-f0-9]{32})-", image_tag)
    run_id = match.group(1) if match else uuid.uuid4().hex
    return ["--label", f"{docker_resources.OWNER_LABEL}={docker_resources.owner_id()}",
            "--label", f"{docker_resources.RUN_LABEL}={run_id}"]


def _label_compose(work_dir, run_id):
    """Own only generated builds, never retag or delete external shared images."""
    path = os.path.join(work_dir, "docker-compose.yml")
    if not os.path.isfile(path):
        return
    import yaml
    with open_utf8(path) as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict) or not data.get("services"):
        return
    labels = {docker_resources.OWNER_LABEL: docker_resources.owner_id(), docker_resources.RUN_LABEL: run_id}
    for index, service in enumerate(data["services"].values()):
        service["labels"] = dict(labels)
        service["logging"] = {"driver": "local", "options": {"max-size": "10m", "max-file": "2"}}
        if "build" in service:
            build = service["build"]
            if isinstance(build, str):
                build = {"context": build}
            build["labels"] = dict(labels)
            service["build"] = build
            service["image"] = f"openant-{run_id}-{index}:latest"
    for network in data.get("networks", {}).values():
        network["labels"] = dict(labels)
    with open_utf8(path, "w") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)
