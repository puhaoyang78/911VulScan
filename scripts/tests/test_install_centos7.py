"""Hermetic CentOS 7 orchestration checks, not a real old-kernel deployment."""
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64
MARKER = "# Managed by 911VulScan CentOS 7 installer"

DISPATCH = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['TEST_ROOT'])
args = sys.argv[1:]
command = Path(sys.argv[0]).name
with (root / 'actions').open('a') as log:
    log.write(json.dumps([command, *args]) + '\n')
state_file = root / 'state'
state = json.loads(state_file.read_text())
def save(): state_file.write_text(json.dumps(state))
def fail_when(name):
    if os.environ.get(name) == '1': sys.exit(1)
if command == 'uname': print(os.environ.get('ARCH', 'x86_64') if args == ['-m'] else os.environ.get('KERNEL', '3.10.0-957.27.6.d3d8ea1.el7.x86_64'))
elif command == 'id':
    print({'-u': '997' if len(args)>1 else os.environ.get('CALLER_UID','0'), '-g':'998', '-gn':'vulscan'}[args[0]])
elif command == 'getent':
    if args[0] == 'group': print('docker:x:999:')
    elif state.get('account', True): print('vulscan:x:997:998::/var/lib/vulscan:/sbin/nologin')
    else: sys.exit(2)
elif command == 'stat': print('999')
elif command == 'rpm': sys.exit(1)
elif command == 'useradd': state['account'] = True; save()
elif command == 'runuser': sys.exit(0)
elif command == 'sha256sum': fail_when('BAD_KEY')
elif command == 'curl': Path(args[args.index('--output')+1]).write_text('verified-key-fixture')
elif command == 'yum': fail_when('YUM_FAIL')
elif command == 'install':
    if '-d' not in args:
        shutil = __import__('shutil')
        shutil.copyfile(args[-2], args[-1])
        os.chmod(args[-1], int(args[args.index('-m')+1], 8))
elif command == 'systemctl':
    action = args[0]
    if action == 'is-active': sys.exit(0 if state.get('running') else 3)
    if action == 'show': print('ActiveState=' + os.environ.get('SERVICE_STATE', 'active' if state.get('running') else 'inactive'))
    if action == 'stop': state.update(running=False, container=False); save()
    if action == 'restart':
        fail_when('START_FAIL')
        unit = (root/'systemd/vulscan.service').read_text()
        image = next(line.split('=', 2)[2] for line in unit.splitlines() if line.startswith('Environment=VULSCAN_IMAGE='))
        state.update(running=True, container=True, image=image); save()
elif command == 'docker':
    if args[0] == 'version': print(os.environ.get('ENGINE', '26.1.4'))
    elif args[0] == 'info': print(os.environ.get('SECURITY', '["name=seccomp"]'))
    elif args[:2] == ['container','ls']:
        if not state.get('running'): fail_when('LIST_FAIL_AFTER_STOP')
        if 'id=abc123' in args and state.get('pending_removal'):
            state['pending_removal'] -= 1
            if not state['pending_removal']: state['container'] = False
            save()
        print('abc123' if state.get('container') else '')
    elif args[:2] == ['container','inspect']:
        print(os.environ.get('CONTAINER_LABEL', 'centos7') + ' true ' + state['image'])
    elif args[0] == 'inspect':
        if 'Config.Labels' in args[2]: print(os.environ.get('CONTAINER_LABEL', 'centos7'))
        else: print(('true ' + state['image']) if '.Image' in args[2] else 'true')
    elif args[0] == 'stop':
        pending = int(os.environ.get('REMOVAL_DELAY', '0'))
        state.update(running=False, container=bool(pending), pending_removal=pending); save()
    elif args[0] == 'build':
        fail_when('BUILD_FAIL')
        context = Path(args[-1])
        (root/'context-files').write_text('\n'.join(sorted(p.relative_to(context).as_posix() for p in context.rglob('*') if p.is_file())))
        Path(args[args.index('--iidfile')+1]).write_text('sha256:'+'2'*64)
    elif args[0] == 'exec':
        if '--idle-url' in args:
            state['idle_calls'] = state.get('idle_calls',0)+1; save()
            fail_when('ACTIVE_SCANS')
            if state['idle_calls'] > 1: fail_when('ACTIVE_AFTER_BUILD')
        fail_when('VERIFY_FAIL')
    elif args[0] == 'run': fail_when('RUN_FAIL')
'''


class CentOSInstallerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="vulscan-centos7-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / 'mockbin'
        self.bin.mkdir()
        for directory in ('scripts', 'systemd', 'libexec', 'apps/vulscan-cli', 'libs/vulscan-core/vulscan', 'config'):
            (self.root / directory).mkdir(parents=True)
        shutil.copy(SCRIPTS/'install-centos7.sh', self.root/'scripts/install-centos7.sh')
        shutil.copy(SCRIPTS/'centos7.Dockerfile', self.root/'scripts/centos7.Dockerfile')
        shutil.copy(SCRIPTS/'stop-centos7.sh', self.root/'scripts/stop-centos7.sh')
        for name in ('scripts/install-deployment.sh', 'scripts/check-deployment.py',
                     'scripts/configure-ubuntu-mirrors.sh', 'scripts/select-docker-packages.py', 'apps/vulscan-cli/main.go',
                     'libs/vulscan-core/vulscan/__main__.py', 'config/models.json', 'config/languages.json'):
            (self.root/name).write_text('fixture')
        self.unit = self.root/'systemd/vulscan.service'
        self.env = dict(os.environ, TEST_ROOT=str(self.root), PATH=str(self.bin),
                        VULSCAN_SYSTEMD_DIR=str(self.unit.parent), VULSCAN_OS_RELEASE=str(self.root/'os-release'),
                        VULSCAN_LIBEXEC_DIR=str(self.root/'libexec'),
                        VULSCAN_DOCKER_SOCKET=str(self.root/'docker.sock'))
        local_socket = socket.socket(socket.AF_UNIX)
        self.addCleanup(local_socket.close)
        local_socket.bind(self.env['VULSCAN_DOCKER_SOCKET'])
        for name in ('DOCKER_HOST', 'DOCKER_CONTEXT'):
            self.env.pop(name, None)
        (self.root/'os-release').write_text('ID="centos"\nVERSION_ID="7"\n')
        self.set_state(running=False, container=False, account=True)
        for name in ('dirname', 'sed', 'tr', 'grep', 'mktemp', 'rm', 'mkdir', 'cat', 'tar', 'cut', 'flock'):
            (self.bin/name).symlink_to(shutil.which(name))
        for name in ('uname', 'id', 'getent', 'stat', 'rpm', 'useradd', 'runuser', 'sha256sum', 'curl', 'yum',
                     'install', 'systemctl', 'docker', 'dockerd', 'sleep'):
            script = self.bin/name
            script.write_text('#!'+sys.executable+'\n'+DISPATCH)
            script.chmod(0o755)

    def set_state(self, **values):
        (self.root/'state').write_text(json.dumps(values))

    def old_service(self):
        self.unit.write_text(MARKER+'\nEnvironment=VULSCAN_IMAGE='+OLD+'\n')
        self.set_state(running=True, container=True, account=True, image=OLD)

    def actions(self):
        path = self.root/'actions'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run_script(self, *args, success=True):
        result = subprocess.run(['/bin/bash', str(self.root/'scripts/install-centos7.sh'), *args],
                                env=self.env, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode == 0, success, result.stdout+'\n'+result.stderr)
        return result

    def test_plan_for_supplied_server_is_read_only(self):
        self.run_script('--dry-run')
        self.assertTrue(all(a[0] == 'uname' for a in self.actions()))
        self.assertFalse(self.unit.exists())

    def test_reject_unsupported_system_arch_and_kernel(self):
        for change in ({'ARCH':'aarch64'}, {'KERNEL':'3.10.0-327.el7.x86_64'}, {'KERNEL':'2.6.32-754.el6.x86_64'}):
            with self.subTest(change=change):
                old = dict(self.env); self.env.update(change)
                self.run_script('--dry-run', success=False)
                self.env = old
        (self.root/'os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        self.run_script('--dry-run', success=False)

    def test_first_deployment_nonroot_runtime_and_systemd219(self):
        self.run_script()
        unit = self.unit.read_text()
        self.assertIn('User=vulscan\nSupplementaryGroups=docker', unit)
        self.assertIn('Environment=VULSCAN_IMAGE='+NEW, unit)
        self.assertIn('--user 997:998 --group-add 999', unit)
        self.assertIn('--network host', unit)
        self.assertIn('StartLimitInterval=60', unit)
        self.assertIn('${VULSCAN_IMAGE}', unit)
        self.assertIn('ExecStartPre='+str(self.root/'libexec/vulscan-centos7-stop'), unit)
        self.assertIn('ExecStop='+str(self.root/'libexec/vulscan-centos7-stop'), unit)
        self.assertNotIn('StartLimitIntervalSec', unit)
        actions = self.actions()
        self.assertIn(['systemctl','enable','docker','vulscan'], actions)
        self.assertLess(actions.index(['systemctl','reset-failed','vulscan']), actions.index(['systemctl','restart','vulscan']))
        self.assertFalse(any('--value' in a for a in actions))
        for a in actions:
            if a[:2] == ['docker','exec']:
                self.assertEqual(a[2:4], ['--user','997:998'])

    def test_context_includes_entrypoints_and_excludes_secrets(self):
        for name in ('apps/vulscan-cli/.env', 'libs/vulscan-core/.env.local',
                     'apps/vulscan-cli/vulscan', 'apps/vulscan-cli/main_test.go'):
            (self.root/name).write_text('secret-or-generated')
        self.run_script()
        files = set((self.root/'context-files').read_text().splitlines())
        self.assertIn('apps/vulscan-cli/main.go', files)
        self.assertIn('libs/vulscan-core/vulscan/__main__.py', files)
        self.assertFalse(any('.env' in f or f.endswith('main_test.go') or f == 'apps/vulscan-cli/vulscan' for f in files))
        self.assertTrue(any(a[:2] == ['docker','build'] and a[2:4] == ['--network','host'] for a in self.actions()))

    def test_context_contains_all_local_dockerfile_copy_sources(self):
        self.run_script()
        files = set((self.root/'context-files').read_text().splitlines())
        for line in (self.root/'scripts/centos7.Dockerfile').read_text().splitlines():
            if not line.startswith('COPY '):
                continue
            words = shlex.split(line, comments=True)
            if words[1].startswith('--from='):
                continue
            for source in words[1:-1]:
                source = source.rstrip('/')
                with self.subTest(source=source):
                    self.assertTrue(source in files or any(name.startswith(source+'/') for name in files),
                                    f'Dockerfile COPY source missing from build context: {source}')

    def test_missing_build_helpers_fail_before_build_and_preserve_old_service(self):
        self.old_service()
        for name in ('configure-ubuntu-mirrors.sh', 'select-docker-packages.py'):
            source = self.root/'scripts'/name
            contents = source.read_bytes()
            with self.subTest(source=name):
                source.unlink()
                try:
                    result = self.run_script(success=False)
                finally:
                    source.write_bytes(contents)
                self.assertIn(f'缺少 scripts/{name}', result.stderr)
                self.assertFalse(any(a[:2] in (['docker','build'], ['systemctl','stop']) for a in self.actions()))
                self.assertIn(OLD, self.unit.read_text())

    def test_stop_waits_for_asynchronous_removal(self):
        self.old_service(); self.env['REMOVAL_DELAY'] = '3'
        result = subprocess.run(['/bin/bash', str(SCRIPTS/'stop-centos7.sh'), str(self.bin/'docker'), '911vulscan'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(a[0] == 'sleep' for a in self.actions()), 2)
        self.assertFalse(json.loads((self.root/'state').read_text())['container'])

    def test_stop_does_not_touch_foreign_containers(self):
        self.old_service(); self.env['CONTAINER_LABEL'] = 'other'
        result = subprocess.run(['/bin/bash', str(SCRIPTS/'stop-centos7.sh'), str(self.bin/'docker'), '911vulscan'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(a[:2] == ['docker','stop'] for a in self.actions()))

    def test_stop_query_failure_is_not_reported_as_removal(self):
        self.old_service(); self.env.update(REMOVAL_DELAY='3', LIST_FAIL_AFTER_STOP='1')
        result = subprocess.run(['/bin/bash', str(SCRIPTS/'stop-centos7.sh'), str(self.bin/'docker'), '911vulscan'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(json.loads((self.root/'state').read_text())['container'])

    def test_repeat_deployment_checks_idle_twice_and_replaces_image(self):
        self.old_service()
        self.run_script()
        state = json.loads((self.root/'state').read_text())
        self.assertEqual(state['idle_calls'], 2)
        self.assertEqual(state['image'], NEW)
        self.assertIn(['systemctl','stop','vulscan'], self.actions())

    def test_activity_blocks_update_before_build(self):
        self.old_service(); self.env['ACTIVE_SCANS'] = '1'
        self.run_script(success=False)
        self.assertFalse(any(a[:2] in (['docker','build'], ['systemctl','stop']) for a in self.actions()))
        self.assertIn(OLD, self.unit.read_text())

    def test_activity_started_during_build_preserves_old_service(self):
        self.old_service(); self.env['ACTIVE_AFTER_BUILD'] = '1'
        self.run_script(success=False)
        self.assertNotIn(['systemctl','stop','vulscan'], self.actions())
        self.assertIn(OLD, self.unit.read_text())

    def test_interrupted_build_retries_without_stopping_old_service(self):
        self.old_service(); self.env['BUILD_FAIL'] = '1'
        self.run_script(success=False)
        self.assertNotIn(['systemctl','stop','vulscan'], self.actions())
        self.env.pop('BUILD_FAIL')
        self.run_script()
        self.assertIn(NEW, self.unit.read_text())

    def test_failed_prerequisite_probe_preserves_old_service(self):
        self.old_service(); self.env['RUN_FAIL'] = '1'
        self.run_script(success=False)
        self.assertNotIn(['systemctl','stop','vulscan'], self.actions())

    def test_unmanaged_service_and_container_are_not_overwritten(self):
        self.unit.write_text('[Service]\nUser=root\n')
        self.run_script(success=False)
        self.assertEqual(self.unit.read_text(), '[Service]\nUser=root\n')
        self.old_service(); self.env['CONTAINER_LABEL'] = 'other'
        self.run_script(success=False)
        self.assertNotIn(['systemctl','stop','vulscan'], self.actions())

    def test_root_and_local_daemon_required(self):
        self.env['CALLER_UID'] = '1000'
        self.run_script(success=False)
        self.env['CALLER_UID'] = '0'; self.env['DOCKER_HOST'] = 'tcp://other:2375'
        self.run_script(success=False)
        self.assertFalse(any(a[:2] == ['systemctl','start'] for a in self.actions()))

    def test_existing_incompatible_engine_and_selinux_are_not_relaxed(self):
        self.env['ENGINE'] = '19.03.15'; self.run_script(success=False)
        self.env['ENGINE'] = '26.1.4'; self.env['SECURITY'] = '["name=selinux"]'
        self.run_script(success=False)
        self.assertFalse(self.unit.exists())

    def test_check_uses_current_image_and_does_not_restart(self):
        self.old_service(); self.run_script('--check')
        actions = self.actions()
        self.assertFalse(any(a[:2] in (['systemctl','restart'], ['systemctl','start'], ['docker','build']) for a in actions))
        checks = [a for a in actions if a[:2] == ['docker','exec']]
        self.assertEqual(len(checks), 3)
        self.assertTrue(any('--docker' in a for a in checks))


if __name__ == '__main__':
    unittest.main()
