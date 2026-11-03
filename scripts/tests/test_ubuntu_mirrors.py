"""Real source-file transformations, without touching the host's APT settings."""
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / 'configure-ubuntu-mirrors.sh'


def configure(root, check=True):
    result = subprocess.run(['/bin/sh', str(SCRIPT), str(root)], capture_output=True, text=True, check=check)
    return result.stdout.count('Ubuntu mirror updated:') if check else result


class UbuntuMirrorTests(unittest.TestCase):
    def test_legacy_lists_and_deb822_preserve_trust_and_components(self):
        for suite in ('focal', 'jammy', 'noble'):
            with self.subTest(suite=suite), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'sources.list.d').mkdir()
                classic = root / 'sources.list'
                classic.write_text('deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://cn.archive.ubuntu.com/ubuntu/ ' + suite + ' main universe\n'
                                   'deb https://security.ubuntu.com/ubuntu ' + suite + '-security main\n'
                                   'deb https://packages.example.com/ubuntu ' + suite + ' main\n')
                classic.chmod(0o640)
                deb822 = root / 'sources.list.d/ubuntu.sources'
                original = ('Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/\n'
                            'Suites: ' + suite + ' ' + suite + '-updates\nComponents: main universe\n'
                            'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n')
                deb822.write_text(original)
                self.assertEqual(configure(root), 2)
                self.assertIn('http://mirrors.aliyun.com/ubuntu', classic.read_text())
                self.assertIn('deb https://packages.example.com/ubuntu', classic.read_text())
                self.assertEqual(classic.stat().st_mode & 0o777, 0o640)
                self.assertEqual(deb822.read_text(), original.replace('http://archive.ubuntu.com', 'http://mirrors.aliyun.com').replace('http://security.ubuntu.com', 'http://mirrors.aliyun.com'))
                self.assertNotIn('trusted=yes', classic.read_text())
                self.assertEqual(configure(root), 0)

    def test_arm_ports_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'sources.list'
            source.write_text('deb http://ports.ubuntu.com/ubuntu-ports noble main universe\n')
            configure(root)
            self.assertIn('http://mirrors.aliyun.com/ubuntu-ports', source.read_text())
            target = root / 'target'
            source.rename(target)
            source.symlink_to(target)
            result = configure(root, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('non-regular', result.stderr)


if __name__ == '__main__':
    unittest.main()
