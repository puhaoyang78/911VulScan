"""Hermetic installer tests: no sudo, apt, downloads, builds or services run."""
from pathlib import Path
import json
import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'install-deployment.sh'


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vulscan's mocked path ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'scripts').mkdir()
        shutil.copy(SCRIPT, self.root / 'scripts/install-deployment.sh')
        self.bin = self.root / 'mockbin'
        self.bin.mkdir()
        # Closed PATH: only these non-mutating/core file tools can reach real binaries.
        for name in ['dirname', 'sed', 'tr', 'awk', 'grep', 'mkdir', 'mktemp', 'rm', 'mv', 'chmod', 'sha256sum', 'cat']:
            (self.bin / name).symlink_to(shutil.which(name))
        self.env = dict(os.environ, PATH=str(self.bin), TEST_ROOT=str(self.root), REAL_PYTHON=sys.executable,
                        VULSCAN_OS_RELEASE=str(self.root / 'os-release'), ARCH='x86_64', NODE_VERSION='v22.15.0',
                        GO_VERSION='1.26.1', NPM_VERSION='10.9.0', PYTHON_READY='1', DOCKER_READY='1')
        self.os('24.04')
        self.mock('uname', 'echo "$ARCH"')
        self.mock('id', 'echo 1000')
        self.mock('sudo', 'echo "sudo $*" >> "$TEST_ROOT/actions"; shift; exec "$@"')
        self.mock('apt-get', 'echo "apt $*" >> "$TEST_ROOT/actions"; exit "${APT_EXIT:-0}"')
        self.mock('apt-cache', 'echo "  Candidate: ${CANDIDATE:-1.0}"')
        self.mock('dpkg-query', '[ "${CONFLICT:-}" = "$3" ] && printf "install ok installed"')
        self.mock('systemctl', 'echo "service $*" >> "$TEST_ROOT/actions"; exit "${SERVICE_EXIT:-0}"')
        self.mock('python3', '''
if [ "$1" = -c ]; then [ "$PYTHON_READY" = 1 ]; exit; fi
if [ "$1" = -m ]; then
  echo "python $*" >> "$TEST_ROOT/actions"
  mkdir -p "$3/bin"
  printf '#!/bin/sh\\necho "pip $*" >> "$TEST_ROOT/actions"\\n' > "$3/bin/python"
  chmod +x "$3/bin/python"
  exit
fi
exec "$REAL_PYTHON" "$@"
''')
        self.mock('go', 'if [ "$1" = version ]; then echo "go version go$GO_VERSION linux/amd64"; else echo "go $*" >> "$TEST_ROOT/actions"; fi')
        self.mock('node', 'echo "$NODE_VERSION"')
        self.mock('npm', 'if [ "$1" = --version ]; then echo "$NPM_VERSION"; else echo "npm $*" >> "$TEST_ROOT/actions"; fi')
        self.mock('dockerd', '[ "$DOCKER_READY" = 1 ] && echo Docker-version-28.1.1')
        self.mock('docker', '''
[ "$DOCKER_READY" = 1 ] || exit 1
case "$1" in --version) echo 'Docker version 28.1.1';; compose) echo 2.35.1;; buildx) echo 'buildx v0.23.0';; esac
''')
        self.mock('curl', '''
echo "download $*" >> "$TEST_ROOT/actions"
[ "${DOWNLOAD_FAIL:-0}" = 0 ] || exit 22
while [ "$1" != --output ]; do shift; done
out=$2; url=$3
case "$url" in *mode=json*) cat "$TEST_ROOT/go.json" > "$out";; *) printf 'invalid archive' > "$out";; esac
''')
        self.mock('tar', 'echo "EXTRACT $*" >> "$TEST_ROOT/actions"; exit 98')
        self.mock('make', 'echo "BUILD $*" >> "$TEST_ROOT/actions"; exit 98')
        (self.root / 'go.json').write_text(json.dumps([{'version': 'go1.26.1', 'stable': True, 'files': [
            {'filename': f'go1.26.1.linux-{a}.tar.gz', 'os': 'linux', 'arch': a, 'kind': 'archive', 'sha256': '0' * 64}
            for a in ['amd64', 'arm64']]}]))

    def mock(self, name, body):
        p = self.bin / name
        if p.is_symlink():
            p.unlink()
        p.write_text('#!/bin/sh\n' + body + '\n')
        p.chmod(0o755)

    def os(self, version, distro='ubuntu'):
        (self.root / 'os-release').write_text(f'ID={distro}\nVERSION_ID="{version}"\n')

    def run_script(self, *args, success=True):
        result = subprocess.run(['/bin/sh', str(self.root / 'scripts/install-deployment.sh'), *args],
                                env=self.env, text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def actions(self):
        p = self.root / 'actions'
        return p.read_text() if p.exists() else ''

    def test_check_ready_readonly(self):
        self.run_script('--check')
        self.assertEqual(self.actions(), '')
        self.assertFalse((self.root / '.tools').exists())

    def test_version_branches(self):
        for key, versions in [('GO_VERSION', ['1.25.9', 'devel', '1.26rc1']),
                              ('NODE_VERSION', ['v18.20.0', 'v21.7.0']), ('NPM_VERSION', ['6.14.0'])]:
            old = self.env[key]
            for v in versions:
                with self.subTest(key=key, version=v):
                    self.env[key] = v
                    self.run_script('--check', success=False)
            self.env[key] = old
        for v in ['v20.0.0', 'v22.0.0', 'v24.1.0']:
            self.env['NODE_VERSION'] = v
            self.run_script('--check')
        self.assertEqual(self.actions(), '')

    def test_dry_run_missing_no_side_effects(self):
        self.env.update(PYTHON_READY='0', GO_VERSION='1.20.0', NODE_VERSION='v18.0.0', DOCKER_READY='0')
        # No CLI exists, rather than an unmanaged partial installation.
        (self.bin / 'docker').unlink()
        for version in ['20.04', '22.04', '24.04', '26.04']:
            for arch in ['x86_64', 'aarch64']:
                self.os(version); self.env['ARCH'] = arch
                self.run_script('--install-deps', '--dry-run')
        self.assertEqual(self.actions(), '')
        self.assertFalse((self.root / '.tools').exists())

    def test_unsupported_platforms(self):
        self.os('13', 'debian')
        self.assertIn('supports Ubuntu', self.run_script('--install-deps', '--dry-run', success=False))
        self.os('24.04'); self.env['ARCH'] = 'riscv64'
        self.assertIn('Unsupported architecture', self.run_script('--install-deps', '--yes', success=False))
        self.assertEqual(self.actions(), '')

    def test_requires_noninteractive_consent(self):
        self.assertIn('requires --yes', self.run_script('--install-deps', success=False))
        self.assertEqual(self.actions(), '')

    def test_docker_service_and_focal_consent(self):
        (self.bin / 'docker').unlink()
        self.assertIn('--start-docker', self.run_script('--install-deps', '--yes', success=False))
        self.os('20.04')
        self.assertIn('--allow-unsupported-docker', self.run_script('--install-deps', '--yes', '--start-docker', success=False))
        self.assertEqual(self.actions(), '')

    def test_docker_conflict(self):
        self.env.update(DOCKER_READY='0', CONFLICT='docker-ce')
        self.assertIn('refusing to replace', self.run_script('--install-deps', '--yes', '--start-docker', success=False))
        self.assertEqual(self.actions(), '')

    def test_no_privilege_when_ready(self):
        self.run_script('--install-deps', '--deps-only', '--yes')
        self.assertEqual(self.actions(), '')

    def test_service_failure(self):
        self.env['SERVICE_EXIT'] = '1'
        self.assertIn('could not start', self.run_script('--install-deps', '--deps-only', '--yes', '--start-docker', success=False))
        self.assertIn('service start docker', self.actions())

    def test_checksum_failure_no_extract(self):
        self.env['GO_VERSION'] = '1.25.0'
        self.assertIn('checksum mismatch', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertNotIn('EXTRACT', self.actions())
        self.assertFalse((self.root / '.tools/go').exists())
        self.assertEqual(list((self.root / '.tools').iterdir()), [])

    def test_download_failure_no_fallback(self):
        self.env.update(GO_VERSION='1.25.0', DOWNLOAD_FAIL='1')
        self.assertIn('no alternate mirror', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertEqual(self.actions().count('download '), 1)
        self.assertNotIn('EXTRACT', self.actions())

    def test_package_failure(self):
        self.env.update(GO_VERSION='1.25.0', APT_EXIT='1')
        self.assertIn('APT update failed', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertNotIn('download ', self.actions())

    def test_missing_candidate(self):
        self.env.update(GO_VERSION='1.25.0', CANDIDATE='(none)')
        self.assertIn('No APT candidate', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertNotIn('apt install', self.actions())

    def test_default_application_no_sudo(self):
        for name in ['libs/vulscan-core/parsers/javascript', 'apps/vulscan-cli']:
            (self.root / name).mkdir(parents=True)
        self.run_script()
        self.assertNotIn('sudo', self.actions())
        self.assertNotIn('apt ', self.actions())
        self.assertIn('npm ci --engine-strict', self.actions())
        self.assertIn('.tools/node/bin', (self.root / 'bin/vulscan').read_text())

    def test_invalid_arguments(self):
        for args in [('--unknown',), ('--deps-only',), ('--yes',), ('--start-docker',), ('--check', '--dry-run')]:
            self.run_script(*args, success=False)
        self.assertEqual(self.actions(), '')

    def full_download_fixtures(self, malicious=False):
        """Synthetic archives/commands; deliberately does not install real packages."""
        pins = {'docker-ce': '5:28.1.1-1~ubuntu.20.04~focal', 'docker-ce-cli': '5:28.1.1-1~ubuntu.20.04~focal',
                'containerd.io': '1.7.27-1', 'docker-compose-plugin': '2.35.1-1~ubuntu.20.04~focal',
                'docker-buildx-plugin': '0.23.0-1~ubuntu.20.04~focal'}
        blocks = []
        for name, version in pins.items():
            filename = f'dists/focal/pool/stable/amd64/{name}_fixture_amd64.deb'
            if malicious and name == 'docker-ce':
                filename = 'dists/focal/pool/stable/amd64/../../evil.deb'
            blocks.append(f'Package: {name}\nVersion: {version}\nArchitecture: amd64\nFilename: {filename}\nSHA256: {"0" * 64}\n')
        (self.root / 'docker.gz').write_bytes(gzip.compress('\n'.join(blocks).encode()))
        (self.root / 'node.json').write_text('[{"version":"v22.15.0","lts":"Jod"}]')
        self.mock('sha256sum', 'echo "checksum $*" >> "$TEST_ROOT/actions"; exit 0')
        self.mock('curl', r"""
echo "download $*" >> "$TEST_ROOT/actions"
while [ "$1" != --output ]; do shift; done
out=$2; url=$3
case "$url" in
  *mode=json*) cat "$TEST_ROOT/go.json" > "$out";;
  *Packages.gz) cat "$TEST_ROOT/docker.gz" > "$out";;
  *index.json) cat "$TEST_ROOT/node.json" > "$out";;
  *SHASUMS256.txt) printf '%064d  node-v22.15.0-linux-x64.tar.gz\n' 0 > "$out";;
  *) printf fixture > "$out";;
esac
""")
        self.mock('tar', r"""
echo "EXTRACT $*" >> "$TEST_ROOT/actions"
archive=$2
while [ "$1" != -C ]; do shift; done
out=$2
case "$archive" in
  *Python-*) mkdir -p "$out/Python-3.12.15"; printf '#!/bin/sh\nexit 0\n' > "$out/Python-3.12.15/configure"; chmod +x "$out/Python-3.12.15/configure";;
  *go1*) mkdir -p "$out/go/bin"; printf '#!/bin/sh\necho "go version go1.26.1 linux/amd64"\n' > "$out/go/bin/go"; chmod +x "$out/go/bin/go";;
  *node-*) mkdir -p "$out/bin"; printf '#!/bin/sh\necho v22.15.0\n' > "$out/bin/node"; printf '#!/bin/sh\necho 10.9.0\n' > "$out/bin/npm"; chmod +x "$out/bin/node" "$out/bin/npm";;
esac
""")
        self.mock('make', r"""
echo "BUILD $*" >> "$TEST_ROOT/actions"
if [ "$1" = altinstall ]; then
  mkdir -p "$TEST_ROOT/.tools/python/bin"
  printf '#!/bin/sh\nexport PYTHON_READY=1\nexec "$TEST_ROOT/mockbin/python3" "$@"\n' > "$TEST_ROOT/.tools/python/bin/python3.12"
  chmod +x "$TEST_ROOT/.tools/python/bin/python3.12"
fi
""")
        self.mock('apt-get', r"""
echo "apt $*" >> "$TEST_ROOT/actions"
case "$*" in *.deb*) printf ready > "$TEST_ROOT/docker-ready";; esac
exit 0
""")
        # No CLI before bootstrap, but apt fixture installs the two mocked binaries.
        self.mock('apt-get', (self.bin / 'apt-get').read_text().split('\n', 1)[1].replace(
            'printf ready > "$TEST_ROOT/docker-ready"',
            'printf ready > "$TEST_ROOT/docker-ready"; cat "$TEST_ROOT/docker-template" > "$TEST_ROOT/mockbin/docker"; chmod +x "$TEST_ROOT/mockbin/docker"'))
        (self.root / 'docker-template').write_text('#!/bin/sh\ncase "$1" in compose) echo 2.35.1;; *) echo Docker28.1.1;; esac\n')
        self.mock('dockerd', '[ -f "$TEST_ROOT/docker-ready" ]')
        (self.bin / 'docker').unlink()

    def test_focal_success_fully_mocked(self):
        self.os('20.04')
        self.env.update(PYTHON_READY='0', GO_VERSION='1.25.0', NODE_VERSION='v18.0.0')
        self.full_download_fixtures()
        self.run_script('--install-deps', '--deps-only', '--yes', '--start-docker', '--allow-unsupported-docker')
        actions = self.actions()
        self.assertIn('BUILD altinstall', actions)
        self.assertIn('python-venv-check', actions)
        self.assertIn('Packages.gz', actions)
        self.assertIn('--no-remove --no-install-recommends', actions)
        self.assertIn('service start docker', actions)
        self.assertNotIn('usermod', actions)
        self.assertEqual(sorted(p.name for p in (self.root / '.tools').iterdir()), ['go', 'node', 'python'])

    def test_malicious_docker_metadata(self):
        self.os('20.04')
        self.full_download_fixtures(malicious=True)
        self.assertIn('Invalid filename/checksum', self.run_script('--install-deps', '--deps-only', '--yes', '--start-docker', '--allow-unsupported-docker', success=False))
        self.assertNotIn('.deb https', self.actions())
        self.assertNotIn('service ', self.actions())

    def test_node_checksum_failure(self):
        self.full_download_fixtures()
        self.mock('docker', (self.root / 'docker-template').read_text().split('\n', 1)[1])
        self.mock('dockerd', 'exit 0')
        self.env['NODE_VERSION'] = 'v18.0.0'
        (self.bin / 'sha256sum').unlink()
        (self.bin / 'sha256sum').symlink_to(shutil.which('sha256sum'))
        self.assertIn('Node checksum mismatch', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertNotIn('EXTRACT', self.actions())

    def test_python_checksum_failure(self):
        self.os('20.04')
        self.env['PYTHON_READY'] = '0'
        self.assertIn('Python checksum mismatch', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertNotIn('BUILD', self.actions())

    def test_go_metadata_rejects_traversal(self):
        self.env['GO_VERSION'] = '1.25.0'
        doc = json.loads((self.root / 'go.json').read_text())
        doc[0]['files'][0]['filename'] = '../../evil.tar.gz'
        (self.root / 'go.json').write_text(json.dumps(doc))
        self.assertIn('No stable Go', self.run_script('--install-deps', '--deps-only', '--yes', success=False))
        self.assertEqual(self.actions().count('download '), 1)

    def test_cli_without_engine_not_ready(self):
        (self.bin / 'dockerd').unlink()
        self.assertIn('Docker/Compose/Buildx=1', self.run_script('--check', success=False))

    def test_go_check_disables_toolchain_download(self):
        self.mock('go', '[ "$GOTOOLCHAIN" = local ] || exit 1; echo "go version go1.26.1 linux/amd64"')
        self.run_script('--check')

    def test_incompatible_local_tool_no_system_changes(self):
        (self.root / '.tools/go').mkdir(parents=True)
        self.env['GO_VERSION'] = '1.25.0'
        self.assertIn('move it aside', self.run_script('--install-deps', '--yes', success=False))
        self.assertEqual(self.actions(), '')


if __name__ == '__main__':
    unittest.main()
