#!/usr/bin/env python3
"""Run --deploy on a clean KVM Ubuntu guest, never on the machine running CI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def image_for(version: str, cache: Path) -> Path:
    series = {"20.04": "focal", "22.04": "jammy", "24.04": "noble"}[version]
    base = f"https://cloud-images.ubuntu.com/{series}/current"
    name = f"{series}-server-cloudimg-amd64.img"
    cache.mkdir(parents=True, exist_ok=True)
    sums = subprocess.check_output(["curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3", base + "/SHA256SUMS"], text=True)
    expected, = [line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == name]
    image = cache / name
    if not image.exists():
        temporary = image.with_suffix(".download")
        run("curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3", "--output", str(temporary), base + "/" + name)
        temporary.rename(image)
    with image.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != expected:
        raise RuntimeError(f"{image} differs from the official SHA-256; remove this test image and retry.")
    return image.resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubuntu", choices=("20.04", "22.04", "24.04"), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--guest-proxy", default="", help="Optional test network proxy reachable from the guest")
    args = parser.parse_args()
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("Clean deployment acceptance requires usable KVM; no mocked deployment was run.")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    image = image_for(args.ubuntu, args.image_dir)
    with tempfile.TemporaryDirectory(prefix="vulscan-deploy-vm-") as folder:
        work = Path(folder)
        key = work / "ssh-key"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        user_data = {"users": [{"name": "deployer", "groups": ["sudo"], "sudo": "ALL=(ALL) NOPASSWD:ALL",
                                  "shell": "/bin/bash", "ssh_authorized_keys": [key.with_suffix(".pub").read_text().strip()]}],
                     "ssh_pwauth": False}
        (work / "user-data").write_text("#cloud-config\n" + json.dumps(user_data))
        (work / "meta-data").write_text("instance-id: vulscan-deployment-test\nlocal-hostname: vulscan-deployment-test\n")
        run("cloud-localds", str(work / "seed.img"), str(work / "user-data"), str(work / "meta-data"))
        run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(work / "disk.qcow2"), "16G")
        with socket.socket() as allocation:
            allocation.bind(("127.0.0.1", 0))
            port = allocation.getsockname()[1]
        options = ["-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR"]
        ssh = ["ssh", *options, "-p", str(port), "deployer@127.0.0.1"]
        console = args.output_dir / ("ubuntu-" + args.ubuntu + "-console.log")
        vm = subprocess.Popen(["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", "4096",
                               "-display", "none", "-monitor", "none", "-serial", "file:" + str(console),
                               "-drive", f"file={work / 'disk.qcow2'},if=virtio,format=qcow2",
                               "-drive", f"file={work / 'seed.img'},if=virtio,format=raw",
                               "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
                               "-device", "virtio-net-pci,netdev=net0"])

        def remote(command, **kwargs):
            return run(*ssh, command, **kwargs)

        def wait_boot(previous=""):
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if vm.poll() is not None:
                    raise RuntimeError("Test VM exited; inspect " + str(console))
                result = subprocess.run([*ssh, "cat /proc/sys/kernel/random/boot_id"], check=False, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip() != previous:
                    return result.stdout.strip()
                time.sleep(2)
            raise RuntimeError("Guest boot/SSH timed out; inspect " + str(console))

        def capture(label, command):
            log = args.output_dir / f"ubuntu-{args.ubuntu}-{label}.log"
            print(f"Ubuntu {args.ubuntu}: {label}", flush=True)
            with log.open("w") as output:
                remote(command, stdout=output, stderr=subprocess.STDOUT)

        try:
            boot = wait_boot()
            remote("cloud-init status --wait >/dev/null")
            run("scp", *options, "-P", str(port), str(args.archive.resolve()), "deployer@127.0.0.1:source.tar.gz")
            remote("sudo install -d -o deployer -g deployer /opt/911VulScan && tar -xzf source.tar.gz --strip-components=1 -C /opt/911VulScan")
            environment = ""
            if args.guest_proxy:
                proxy = shlex.quote(args.guest_proxy)
                remote("printf '%s\\n' " + shlex.quote('Acquire::http::Proxy "' + args.guest_proxy + '";\nAcquire::https::Proxy "' + args.guest_proxy + '";') + " | sudo tee /etc/apt/apt.conf.d/99-vulscan-test-proxy >/dev/null")
                environment = f"http_proxy={proxy} https_proxy={proxy} HTTP_PROXY={proxy} HTTPS_PROXY={proxy} "
            installer = "sh /opt/911VulScan/scripts/install-deployment.sh --deploy"
            if args.ubuntu == "20.04":
                deploy = "sudo -n env -u SUDO_USER -u SUDO_UID " + environment + installer
                expected_user = "vulscan"
            elif args.ubuntu == "22.04":
                deploy = "sudo -n env " + environment + installer
                expected_user = "deployer"
            else:
                deploy = "env " + environment + installer
                expected_user = "deployer"

            if args.ubuntu in ("20.04", "22.04"):
                # Interrupt real CPython altinstall, then rerun the exact deploy
                # command. No fake Python, apt, systemd or Docker commands.
                root_command = deploy.removeprefix("sudo -n ")
                pid = remote("sudo sh -c " + shlex.quote("setsid " + root_command + " > /home/deployer/interrupted.log 2>&1 & echo $!"), capture_output=True).stdout.strip()
                print(f"Ubuntu {args.ubuntu}: waiting to interrupt real CPython altinstall", flush=True)
                try:
                    waiting = "until test -d /opt/911VulScan/.tools/python/lib/python3.12; do kill -0 " + str(int(pid)) + " || exit 1; sleep 2; done"
                    remote("sudo timeout 1800 sh -c " + shlex.quote(waiting))
                    remote("sudo kill -TERM -- -" + str(int(pid)))
                    remote("timeout 30 sh -c 'while test -d /proc/" + str(int(pid)) + "; do sleep 1; done'")
                    remote("sudo test -f /opt/911VulScan/.tools/python/.911vulscan-installing && echo keep | sudo tee /opt/911VulScan/.tools/python/deployment-preserved >/dev/null")
                finally:
                    capture("interrupted", "cat /home/deployer/interrupted.log")
            capture("first-deploy", deploy)
            if args.ubuntu in ("20.04", "22.04"):
                remote("grep -qx keep /opt/911VulScan/.tools/python/deployment-preserved && test ! -f /opt/911VulScan/.tools/python/.911vulscan-installing")

            actual = remote("systemctl show -p User --value vulscan", capture_output=True).stdout.strip()
            if actual != expected_user:
                raise AssertionError(f"Expected {expected_user}, service actually runs as {actual}")
            home = remote(f"getent passwd {expected_user} | cut -d: -f6", capture_output=True).stdout.strip()
            first_pid = remote("systemctl show -p MainPID --value vulscan", capture_output=True).stdout.strip()
            first_hash = remote("sha256sum /opt/911VulScan/bin/vulscan-cli | cut -d' ' -f1", capture_output=True).stdout.strip()
            remote(f"echo retained | sudo tee {home}/.vulscan/deployment-preserved >/dev/null")
            record = json.dumps({"id": "deadc0de", "repo": "deployment-history-fixture", "status": "done", "started_at": "2026-10-26T00:00:00Z"})
            remote(f"sudo install -d -o {expected_user} -g {expected_user} {home}/.vulscan/webui/deadc0de && printf '%s' " + shlex.quote(record) + f" | sudo tee {home}/.vulscan/webui/deadc0de/meta.json >/dev/null && sudo chown {expected_user}:{expected_user} {home}/.vulscan/webui/deadc0de/meta.json")
            # Preserve a real Docker client config when its path changes.
            remote(f"sudo install -d -o {expected_user} -g {expected_user} {home}/docker-client && echo '{{\"auths\":{{}}}}' | sudo tee {home}/docker-client/config.json >/dev/null && sudo chown {expected_user}:{expected_user} {home}/docker-client/config.json")
            if args.ubuntu == "24.04":
                # Force the repaired user-local plugin path to be necessary.
                # These are disposable guest files, never host Docker plugins.
                capture("remove-system-plugins", "sudo python3 - <<'PY'\nfrom pathlib import Path\ntarget=Path('/root/deployment-test-original-plugins'); target.mkdir()\ncount=0\nfor directory in ('/usr/libexec/docker/cli-plugins','/usr/lib/docker/cli-plugins','/usr/local/lib/docker/cli-plugins','/usr/local/libexec/docker/cli-plugins'):\n for name in ('docker-compose','docker-buildx'):\n  source=Path(directory)/name\n  if source.is_file():\n   source.rename(target/name); count+=1\nassert count==2, count\nprint('Removed both system plugins in the test guest; redeploy must install service-local plugins.')\nPY")
            remote("python3 - <<'PY'\nfrom pathlib import Path\np=Path('/opt/911VulScan/apps/vulscan-cli/cmd/root.go')\ns=p.read_text(); assert 'var version = \"dev\"' in s\np.write_text(s.replace('var version = \"dev\"', 'var version = \"deployment-acceptance-2\"'))\nPY")
            second = deploy.replace(installer, f"DOCKER_CONFIG={shlex.quote(home + '/docker-client')} " + installer)
            capture("repeat-deploy", second)
            if args.ubuntu == "24.04":
                remote(f"test -x {home}/docker-client/cli-plugins/docker-compose && test -x {home}/docker-client/cli-plugins/docker-buildx")
                capture("repeat-saved-config", deploy)
                remote(f"systemctl show -p Environment --value vulscan | grep -F 'DOCKER_CONFIG={home}/docker-client'")
            second_pid = remote("systemctl show -p MainPID --value vulscan", capture_output=True).stdout.strip()
            second_hash = remote("sha256sum /opt/911VulScan/bin/vulscan-cli | cut -d' ' -f1", capture_output=True).stdout.strip()
            if first_pid == second_pid or first_hash == second_hash:
                raise AssertionError("Redeployment did not restart or did not publish the changed program")
            remote(f"sudo grep -qx retained {home}/.vulscan/deployment-preserved && sudo grep -q auths {home}/docker-client/config.json")
            remote("curl --noproxy '*' -fsS http://127.0.0.1:8080 | grep -q deployment-history-fixture")
            remote("systemctl is-enabled --quiet vulscan && systemctl is-enabled --quiet docker")
            uid = remote(f"id -u {expected_user}", capture_output=True).stdout.strip()
            verify = "sudo /opt/911VulScan/.venv/bin/python /opt/911VulScan/scripts/check-deployment.py --root /opt/911VulScan --url http://127.0.0.1:8080 --service-uid " + uid + " --service-pid $(systemctl show -p MainPID --value vulscan)"
            capture("running-version", verify)
            remote("sudo systemctl kill --kill-who=main --signal=SIGKILL vulscan")
            restarted = 'until systemctl is-active --quiet vulscan && test "$(systemctl show -p MainPID --value vulscan)" -gt 0 && test "$(systemctl show -p MainPID --value vulscan)" != ' + second_pid + '; do sleep 2; done'
            capture("failure-restart", "timeout 90 sh -c " + shlex.quote(restarted) + " && " + verify)
            subprocess.run([*ssh, "sudo systemctl reboot"], check=False)
            wait_boot(boot)
            capture("boot-recovery", "timeout 90 sh -c 'until systemctl is-active --quiet vulscan; do sleep 2; done' && " + verify)
            remote(f"sudo grep -qx retained {home}/.vulscan/deployment-preserved && sudo grep -q auths {home}/docker-client/config.json")
            remote("curl --noproxy '*' -fsS http://127.0.0.1:8080 | grep -q deployment-history-fixture")
            capture("systemd", "systemctl cat vulscan && systemctl status vulscan --no-pager && sudo journalctl -u vulscan --no-pager -n 80")
            print(f"PASS Ubuntu {args.ubuntu}: real --deploy, non-root account, redeploy/version, restart, reboot/data recovery" + (", interrupted Python retry" if args.ubuntu != "24.04" else ""), flush=True)
        except Exception:
            # Diagnostic commands can fail too (e.g. a failed boot). Keep their
            # output and always propagate the original acceptance failure.
            with (args.output_dir / f"ubuntu-{args.ubuntu}-failure.log").open("w") as output:
                try:
                    subprocess.run([*ssh, "sudo journalctl -u vulscan --no-pager -n 120; systemctl show vulscan; df -h /"],
                                   check=False, stdout=output, stderr=subprocess.STDOUT, timeout=20)
                except (OSError, subprocess.TimeoutExpired) as error:
                    print("Failure diagnostics unavailable: " + str(error), file=output)
            raise
        finally:
            vm.terminate()
            try:
                vm.wait(timeout=15)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait()


if __name__ == "__main__":
    main()
