"""Regression checks for bounded VM startup probes; these do not replace KVM acceptance."""
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from deploy_vm import wait_boot


class BootProbeTests(unittest.TestCase):
    def test_reboot_waits_through_timeout_and_old_or_empty_boot_id(self):
        vm = Mock()
        vm.poll.return_value = None
        responses = [
            subprocess.TimeoutExpired('ssh', 10),
            subprocess.CompletedProcess('ssh', 255, '', 'Connection closed'),
            subprocess.CompletedProcess('ssh', 0, 'old-boot\n'),
            subprocess.CompletedProcess('ssh', 0, ''),
            subprocess.CompletedProcess('ssh', 0, 'new-boot\n'),
        ]
        with patch('deploy_vm.subprocess.run', side_effect=responses) as probe, \
                patch('deploy_vm.time.monotonic', side_effect=[0, 0, 1, 2, 3, 4]), \
                patch('deploy_vm.time.sleep') as sleep:
            self.assertEqual(wait_boot(vm, ['ssh', 'test-guest'], Path('console.log'), 'old-boot'), 'new-boot')
        self.assertEqual(probe.call_count, 5)
        self.assertEqual(sleep.call_count, 4)
        self.assertTrue(all(call.kwargs['timeout'] == 10 for call in probe.call_args_list))

    def test_ssh_timeouts_still_fail_at_original_boot_deadline(self):
        vm = Mock()
        vm.poll.return_value = None
        with patch('deploy_vm.subprocess.run', side_effect=subprocess.TimeoutExpired('ssh', 10)) as probe, \
                patch('deploy_vm.time.monotonic', side_effect=[0, 0, 240]), \
                patch('deploy_vm.time.sleep'), \
                self.assertRaisesRegex(RuntimeError, 'Guest boot/SSH timed out; inspect console.log'):
            wait_boot(vm, ['ssh', 'test-guest'], Path('console.log'), 'old-boot')
        self.assertEqual(probe.call_count, 1)

    def test_exited_guest_fails_without_network_probe(self):
        vm = Mock()
        vm.poll.return_value = 1
        with patch('deploy_vm.subprocess.run') as probe, patch('deploy_vm.time.monotonic', return_value=0), \
                self.assertRaisesRegex(RuntimeError, 'Test VM exited'):
            wait_boot(vm, ['ssh', 'test-guest'], Path('console.log'))
        probe.assert_not_called()

    def test_initial_boot_accepts_ready_guest(self):
        vm = Mock()
        vm.poll.return_value = None
        with patch('deploy_vm.subprocess.run', return_value=subprocess.CompletedProcess('ssh', 0, 'first-boot\n')), \
                patch('deploy_vm.time.monotonic', return_value=0), patch('deploy_vm.time.sleep') as sleep:
            self.assertEqual(wait_boot(vm, ['ssh', 'test-guest'], Path('console.log')), 'first-boot')
        sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
