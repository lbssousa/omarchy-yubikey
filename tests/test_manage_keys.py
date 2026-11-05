"""Key management checks with synthetic mappings and mocked FIDO2 tools."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_keys', ROOT / 'scripts/manage-keys.py')
keys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(keys)

MAPPING = ('example_user:first-handle,first-key,es256,+presence+pin:second-handle,second-key,es256,+presence+pin\n'
           'other_user:other-handle,other-key,es256,+presence\n')


def completed(code, stdout=''):
    return subprocess.CompletedProcess([], code, stdout, '')


class DuplicateProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.mapping = Path(self.temp.name) / 'fido2'
        self.mapping.write_text(MAPPING)
        patcher = patch.object(keys, 'MAPPING', self.mapping)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_reads_only_the_selected_account(self):
        self.assertEqual(keys.credentials(MAPPING, 'example_user'),
                         ['first-handle,first-key,es256,+presence+pin', 'second-handle,second-key,es256,+presence+pin'])
        self.assertEqual(keys.credentials(MAPPING, 'missing_user'), [])
        with self.assertRaises(ValueError):
            keys.credentials('example_user:one,a\nexample_user:two,b\n', 'example_user')

    def test_probe_asks_without_touch_for_each_handle(self):
        calls = []
        def run(command, **options):
            calls.append((command, options['input']))
            return completed(0 if 'second-handle' in options['input'] else 1)
        with patch.object(keys.subprocess, 'run', side_effect=run):
            self.assertTrue(keys.already_enrolled('/dev/hidraw-test', keys.credentials(MAPPING, 'example_user')))
        self.assertEqual(len(calls), 2)
        for command, stdin in calls:
            self.assertEqual(command, ['fido2-assert', '-G', '-t', 'up=false', '/dev/hidraw-test'])
            lines = stdin.splitlines()
            self.assertEqual(lines[1], 'pam://omarchy')
            self.assertNotIn('key', lines[2])
        self.assertNotEqual(calls[0][1].splitlines()[0], calls[1][1].splitlines()[0])

    def test_probe_failures_are_not_matches(self):
        with patch.object(keys.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fido2-assert', 5)):
            self.assertFalse(keys.already_enrolled('/dev/hidraw-test', ['handle,key']))
        with patch.object(keys.subprocess, 'run', return_value=completed(1)):
            self.assertFalse(keys.already_enrolled('/dev/hidraw-test', ['handle,key']))

    def test_check_refuses_an_enrolled_key_and_several_devices(self):
        def run(command, **options):
            if command[0] == 'fido2-token':
                return completed(0, '/dev/hidraw-test: vendor=0x0000, product=0x0000 (Example key)\n')
            return completed(0)
        with patch.object(keys.subprocess, 'run', side_effect=run), patch('builtins.print'):
            with self.assertRaises(SystemExit):
                keys.check_new_key('example_user')
        two = completed(0, '/dev/hidraw-a: (Example)\n/dev/hidraw-b: (Example)\n')
        with patch.object(keys.subprocess, 'run', return_value=two):
            with self.assertRaises(ValueError):
                keys.check_new_key('example_user')

    def test_check_accepts_a_new_key_and_a_first_enrollment(self):
        def run(command, **options):
            if command[0] == 'fido2-token':
                return completed(0, '/dev/hidraw-test: (Example key)\n')
            return completed(1)
        with patch.object(keys.subprocess, 'run', side_effect=run) as mocked:
            keys.check_new_key('example_user')
            keys.check_new_key('new_user')
        probes = [call for call in mocked.call_args_list if call.args[0][0] == 'fido2-assert']
        self.assertEqual(len(probes), 2)


if __name__ == '__main__':
    unittest.main()
