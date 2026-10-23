"""Owned Docker resources and conservative shared-builder admission.

Never prune a daemon: image deletion does not reclaim BuildKit cache. Shared
builders are checked against a cache admission budget; the local disk gate cannot
measure a remote daemon's disk. Owners are unguessable scan tokens supplied by the parent.
"""
import argparse
import errno
import getpass
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import tempfile
import time
import uuid

OWNER_LABEL = "io.openant.owner"
RUN_LABEL = "io.openant.run"
_PROCESS_OWNER = uuid.uuid4().hex
_RUN_LEASES = {}
_TOKEN = re.compile(r"[a-f0-9]{32}\Z")


def _token(value):
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError("Docker owner/run must be a 32-character lowercase hex token")
    return value


def owner_id():
    return _token(os.environ.get("OPENANT_DOCKER_OWNER", _PROCESS_OWNER))


def _state_dir(global_lock=False):
    suffix = str(os.getuid()) if hasattr(os, "getuid") else hashlib.sha256(getpass.getuser().encode()).hexdigest()[:16]
    default = Path(tempfile.gettempdir()) / ("openant-docker-resources-" + suffix)
    configured = os.environ.get("OPENANT_DOCKER_REGISTRY_DIR")
    root = default if global_lock or not configured else Path(configured)
    if (not global_lock and configured and os.environ.get("OPENANT_DOCKER_LEASE_FD")
            and not root.exists()):
        raise RuntimeError("Managed Docker registry disappeared; refusing to recreate recovered owner")
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or (os.name != "nt" and info.st_mode & 0o077)):
        raise RuntimeError("Docker lifecycle registry is not a private owned directory")
    return root


def _acquire_run_lease(run_id):
    if not os.environ.get("OPENANT_DOCKER_LEASE_FD") or run_id in _RUN_LEASES:
        return
    import fcntl
    root = _state_dir()
    identity = root.stat()
    fd = os.open(root / ".lease", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        current = root.stat()
        lease = (root / ".lease").stat()
        opened = os.fstat(fd)
        if ((identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino)
                or (lease.st_dev, lease.st_ino) != (opened.st_dev, opened.st_ino)):
            raise RuntimeError("Managed Docker registry changed while acquiring lease")
        _RUN_LEASES[run_id] = fd
    except BaseException:
        os.close(fd)
        raise


def _release_run_lease(run_id):
    fd = _RUN_LEASES.pop(run_id, None)
    if fd is not None:
        os.close(fd)


def register_run(run_id, work_dir):
    run_id = _token(run_id)
    _acquire_run_lease(run_id)
    path = Path(work_dir)
    info = path.lstat()
    # Never let a registry entry authorize deletion outside our staging area.
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or path.parent.resolve() != Path(tempfile.gettempdir()).resolve()
            or not path.name.startswith("openant-test-")):
        raise ValueError("Docker staging directory must be an owned openant-test temporary directory")
    entry = {"owner": owner_id(), "run": run_id, "work_dir": str(path.absolute()),
             "device": info.st_dev, "inode": info.st_ino, "pid": os.getpid()}
    root = _state_dir()
    destination = root / (entry["owner"] + "-" + run_id + ".json")
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entry, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return entry


def _daemon_id(runner):
    out, err, code, timed = runner(["docker", "info", "--format", "{{.ID}}"], timeout=30)
    identity = out.strip()
    if code or timed or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._-]{5,255}", identity):
        raise RuntimeError("Cannot establish Docker daemon identity: " + (err or out or str(code))[:1000])
    return identity


def bind_run_daemon(run_id, runner=None):
    """Pin the actual daemon immediately BEFORE the first resource creation."""
    run_id = _token(run_id)
    root = _state_dir()
    path = root / f"{owner_id()}-{run_id}.json"
    if path.is_symlink():
        raise RuntimeError("Refusing symlink Docker run manifest")
    entry = json.loads(path.read_text(encoding="utf-8"))
    if entry.get("owner") != owner_id() or entry.get("run") != run_id:
        raise RuntimeError("Docker run manifest ownership mismatch")
    identity = _daemon_id(runner or _cleanup_command)
    if entry.get("daemon_id") and entry["daemon_id"] != identity:
        raise RuntimeError("Docker daemon changed during run; refusing resource creation")
    entry["daemon_id"] = identity
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entry, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def forget_run(run_id):
    (_state_dir() / (owner_id() + "-" + _token(run_id) + ".json")).unlink(missing_ok=True)
    _release_run_lease(run_id)


def register_producer(pid):
    """Record a live Docker CLI identity for parent-side crash recovery.

    Import psutil only when needed; the cleanup CLI can still report invalid
    owners or clean an empty registry without loading scanning/LLM packages.
    """
    import psutil
    process = psutil.Process(pid)
    owner = owner_id()
    entry = {"owner": owner, "pid": pid, "created": process.create_time(),
             "parent_pid": os.getpid()}
    root = _state_dir()
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entry, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, root / f"{owner}-{pid}.producer.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def unregister_producer(pid):
    (_state_dir() / f"{owner_id()}-{int(pid)}.producer.json").unlink(missing_ok=True)


def mark_producer_uncertain(pid):
    """Retain evidence when a CLI exits but a descendant still holds its pipes."""
    root = _state_dir()
    path = root / f"{owner_id()}-{int(pid)}.producer.json"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["uncertain_descendants"] = True
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entry, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _stop_producers(owner):
    manifests = list(_state_dir().glob(owner + "-*.producer.json"))
    if not manifests:
        return []
    try:
        import psutil
    except ImportError:
        return ["Cannot safely stop Docker producers: psutil is unavailable"]
    errors = []
    for manifest in manifests:
        stopped = []
        try:
            if manifest.is_symlink():
                raise ValueError("symlink producer manifest")
            entry = json.loads(manifest.read_text(encoding="utf-8"))
            if entry["owner"] != owner or not isinstance(entry["pid"], int) or entry["pid"] <= 1:
                raise ValueError("invalid producer ownership")
            try:
                producer = psutil.Process(entry["pid"])
            except psutil.NoSuchProcess:
                if entry.get("uncertain_descendants"):
                    raise RuntimeError("Docker CLI exited with untracked descendants; operator recovery required")
                manifest.unlink()
                continue
            if producer.create_time() != entry["created"]:
                if entry.get("uncertain_descendants"):
                    raise RuntimeError("Docker CLI identity expired with untracked descendants; operator recovery required")
                # PID recycled: never signal the unrelated replacement process.
                manifest.unlink()
                continue
            # Suspend each known ancestor before discovering its children, so no
            # stopped producer can start new descendants during the tree walk.
            pending = [producer]
            stopped = []
            seen = set()
            while pending:
                process = pending.pop()
                if process.pid in seen:
                    continue
                seen.add(process.pid)
                try:
                    process.suspend()
                    stopped.append(process)
                    pending.extend(process.children())
                except psutil.NoSuchProcess:
                    pass
            for process in reversed(stopped):
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    pass
            _, alive = psutil.wait_procs(stopped, timeout=5)
            # An exited orphan can remain a zombie until its parent reaps it;
            # zombies cannot issue more Docker requests.
            if any(p.is_running() and p.status() != psutil.STATUS_ZOMBIE for p in alive):
                raise RuntimeError("Docker producer did not terminate")
            manifest.unlink()
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, psutil.Error) as exc:
            # If traversal failed after suspension, unknown children may have
            # escaped discovery. Persist uncertainty BEFORE killing their root,
            # otherwise a subsequent retry could mistake the gone root for a
            # safely completed command and delete its recovery evidence.
            if stopped:
                try:
                    entry["uncertain_descendants"] = True
                    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=manifest.parent)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as handle:
                            json.dump(entry, handle)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.replace(temporary, manifest)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                except OSError as record_error:
                    errors.append("Cannot retain producer uncertainty: " + str(record_error))
            # A partial traversal must not leave already-suspended processes
            # frozen indefinitely. Kill what we safely identified; if denied,
            # best-effort resume and retain the manifest/error for the operator.
            for process in reversed(stopped):
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    pass
                except psutil.Error:
                    try:
                        process.resume()
                    except psutil.Error:
                        pass
            errors.append("Docker producer cleanup failed: " + str(exc))
    return errors


def _cleanup_command(cmd, timeout):
    """Small stdlib-only runner for trusted cleanup commands, with bounded pipes."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return "", str(exc), 127, False
    buffers = [bytearray(), bytearray()]
    overflow = [False, False]
    def drain(pipe, index):
        with pipe:
            while True:
                block = pipe.read(8192)
                if not block:
                    return
                available = 1024 * 1024 - len(buffers[index])
                buffers[index].extend(block[:max(0, available)])
                if len(block) > available:
                    overflow[index] = True
    threads = [threading.Thread(target=drain, args=(pipe, index), daemon=True)
               for index, pipe in enumerate((proc.stdout, proc.stderr))]
    for thread in threads:
        thread.start()
    timed = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed = True
        proc.kill()
        proc.wait()
    finally:
        for thread in threads:
            thread.join(timeout=1)
    out, err = (bytes(value).decode("utf-8", errors="replace") for value in buffers)
    if any(overflow) or any(thread.is_alive() for thread in threads):
        return out, err + "\nCleanup output exceeded bounded capture", 125, timed
    return out, err, proc.returncode, timed


def cleanup_owner(owner, run_id=None, runner=None):
    """Remove label-scoped resources; retain recovery entries on any failure.

    Remove image *tags*, not IDs or force-delete: another tag may share the same
    image. This never removes pulled base images or unrelated custom tags.
    Caller must first stop the scan process; this function is not a live reaper.
    """
    owner = _token(owner)
    if run_id is not None:
        run_id = _token(run_id)
    if runner is None:
        runner = _cleanup_command
    filters = ["--filter", f"label={OWNER_LABEL}={owner}"]
    if run_id:
        filters += ["--filter", f"label={RUN_LABEL}={run_id}"]
    # Per-run cleanup must not kill another finding in the same scan. Only
    # whole-owner recovery (after stopping the scanner) terminates producers.
    errors = _stop_producers(owner) if run_id is None else []
    if errors:
        return errors

    def call(cmd):
        out, err, code, timed = runner(cmd, timeout=30)
        if code or timed:
            errors.append(" ".join(cmd[:3]) + ": " + (err or out or str(code))[:1000])
            return None
        return out

    pattern = owner + "-" + (run_id or "*") + ".json"
    manifests = [path for path in _state_dir().glob(pattern)
                 if not path.name.endswith(".producer.json")]
    pinned = set()
    try:
        for manifest in manifests:
            if manifest.is_symlink():
                raise ValueError("symlink lifecycle manifest")
            entry = json.loads(manifest.read_text(encoding="utf-8"))
            if entry.get("owner") != owner or (run_id and entry.get("run") != run_id):
                raise ValueError("manifest ownership mismatch")
            _token(entry.get("run"))
            if "daemon_id" in entry:
                pinned.add(entry["daemon_id"])
        if pinned and (len(pinned) != 1 or _daemon_id(runner) not in pinned):
            raise RuntimeError("Docker daemon identity changed; recovery evidence retained for original daemon")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        return ["Docker cleanup identity check failed: " + str(exc)]

    # A prepared-only run has not issued any mutating Docker request. An empty
    # registry provides no authority/evidence for daemon resource recovery.
    if pinned:
        for kind, listing, removal in (
            ("container", ["docker", "ps", "-aq"], ["docker", "rm", "-f", "-v"]),
            ("network", ["docker", "network", "ls", "-q"], ["docker", "network", "rm"]),
        ):
            output = call(listing + filters)
            if output is not None:
                for resource in set(output.split()):
                    if not re.fullmatch(r"[a-f0-9]{12,64}", resource):
                        errors.append("Invalid Docker " + kind + " ID in cleanup response")
                        continue
                    inspected = call(["docker", kind, "inspect", resource])
                    if inspected is None:
                        continue
                    try:
                        data = json.loads(inspected)[0]
                        labels = ((data.get("Config") or {}).get("Labels") if kind == "container"
                                  else data.get("Labels")) or {}
                        actual_run = labels.get(RUN_LABEL, "")
                        if (labels.get(OWNER_LABEL) != owner or not _TOKEN.fullmatch(actual_run)
                                or (run_id and actual_run != run_id)):
                            raise ValueError("resource ownership labels do not match")
                        call(removal + [resource])
                    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
                        errors.append("Docker " + kind + " cleanup ownership check failed: " + str(exc))
        output = call(["docker", "image", "ls", "-q"] + filters)
        if output is not None:
            for resource in set(output.split()):
                if not re.fullmatch(r"(?:sha256:)?[a-f0-9]{12,64}", resource):
                    errors.append("Invalid Docker image ID in cleanup response")
                    continue
                inspected = call(["docker", "image", "inspect", resource])
                if inspected is None:
                    continue
                try:
                    data = json.loads(inspected)[0]
                    labels = data.get("Config", {}).get("Labels") or {}
                    actual_run = labels.get(RUN_LABEL, "")
                    if labels.get(OWNER_LABEL) != owner or not _TOKEN.fullmatch(actual_run):
                        raise ValueError("image ownership labels do not match")
                    if run_id and actual_run != run_id:
                        raise ValueError("image run label does not match")
                    # Executor owns tags under these run-specific namespaces only.
                    tag_pattern = re.compile(r"openant(?:-test)?-" + actual_run
                                             + r"-[a-z0-9][a-z0-9-]*(?::latest)?\Z")
                    tags = data.get("RepoTags") or []
                    owned = [tag for tag in tags if isinstance(tag, str) and tag_pattern.fullmatch(tag)]
                    for tag in owned:
                        call(["docker", "image", "rm", tag])
                    if not tags:
                        call(["docker", "image", "rm", resource])
                except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
                    errors.append("Docker image cleanup ownership check failed: " + str(exc))
    if not errors:
        pattern = owner + "-" + (run_id or "*") + ".json"
        for manifest in _state_dir().glob(pattern):
            if manifest.name.endswith(".producer.json"):
                continue
            try:
                if manifest.is_symlink():
                    raise ValueError("symlink lifecycle manifest")
                entry = json.loads(manifest.read_text(encoding="utf-8"))
                if entry["owner"] != owner or (run_id and entry["run"] != run_id):
                    raise ValueError("manifest ownership mismatch")
                path = Path(entry["work_dir"])
                if path.exists() or path.is_symlink():
                    info = path.lstat()
                    if (path.is_symlink() or not stat.S_ISDIR(info.st_mode)
                            or path.parent.resolve() != Path(tempfile.gettempdir()).resolve()
                            or not path.name.startswith("openant-test-")
                            or (info.st_dev, info.st_ino) != (entry["device"], entry["inode"])):
                        raise ValueError("staging directory identity changed")
                    shutil.rmtree(path)
                manifest.unlink()
                _release_run_lease(entry["run"])
            except (OSError, ValueError, TypeError, KeyError) as exc:
                errors.append("Docker staging cleanup failed: " + str(exc))
    return errors


def _cache_bytes(runner):
    out, err, code, timed = runner(
        ["docker", "system", "df", "--format", "{{json .}}"], timeout=30)
    if code or timed:
        raise RuntimeError("Cannot inspect Docker cache budget: " + (err or out or str(code))[:1000])
    total = 0
    found = False
    try:
        for line in out.splitlines():
            row = json.loads(line)
            if row.get("Type") != "Build Cache":
                continue
            found = True
            value = row.get("Size", "")
            match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kKMGTPE]?B)\s*", value)
            if not match:
                raise ValueError("unrecognized Build Cache size")
            unit = match[2].upper()
            factor = 1000 ** {"B": 0, "KB": 1, "MB": 2, "GB": 3, "TB": 4, "PB": 5, "EB": 6}[unit]
            total += int(float(match[1]) * factor)
        if not found:
            raise ValueError("Build Cache row missing")
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise RuntimeError("Cannot parse Docker cache budget; no build admitted") from exc
    return total


def _try_build_lock(fd):
    """OS-released nonblocking lock, including noninteractive Windows services."""
    if sys.platform == "win32":
        import msvcrt
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                return False
            raise
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


@contextmanager
def build_admission(timeout=300, runner=None):
    """Serialize local builds and refuse admission above a shared-cache budget.

    The lock is released by the OS on process termination. This is an admission ceiling,
    not a hard storage quota: one build or unrelated daemon users can exceed it.
    The daemon's cache is never pruned. A 2 GiB local free-space floor does not
    measure remote-daemon free space; operators must budget that separately.
    """
    if runner is None:
        runner = _cleanup_command
    try:
        limit = int(os.environ.get("OPENANT_DOCKER_CACHE_MAX_BYTES", str(10 * 1024 ** 3)))
        if limit <= 0:
            raise ValueError()
    except ValueError as exc:
        raise RuntimeError("OPENANT_DOCKER_CACHE_MAX_BYTES must be a positive integer") from exc
    root = _state_dir(global_lock=True)
    fd = os.open(root / "build.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        deadline = time.monotonic() + timeout
        while not _try_build_lock(fd):
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for Docker build admission")
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        if shutil.disk_usage(root).free < 2 * 1024 ** 3:
            raise RuntimeError("Docker build refused: less than 2 GiB local staging disk free; "
                               "remote Docker storage must also be budgeted by the operator")
        if _cache_bytes(runner) >= limit:
            raise RuntimeError("Docker build refused: shared build cache reached the admission budget "
                               f"({limit} bytes); operator cleanup or storage allocation required. "
                               "OpenAnt never prunes shared cache.")
        yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["cleanup"])
    parser.add_argument("--owner", required=True)
    args = parser.parse_args()
    try:
        errors = cleanup_owner(args.owner)
    except (ValueError, OSError, RuntimeError) as exc:
        errors = [str(exc)]
    print(json.dumps({"ok": not errors, "errors": errors}))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
