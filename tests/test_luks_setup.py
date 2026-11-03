import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('luks_setup', ROOT / 'scripts/enroll-luks.py')
luks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(luks)
DEVICE = '/dev/synthetic-luks-test'
BEFORE = {'keyslots': {'0': {'type': 'luks2', 'fixture': 'existing-password'}},
          'tokens': {'1': {'type': 'systemd-fido2', 'keyslots': ['1']}},
          'segments': {'0': {'type': 'crypt', 'fixture': 'existing-volume'}}}
AFTER = copy.deepcopy(BEFORE)
AFTER['keyslots']['2'] = {'type': 'luks2', 'fixture': 'new-key'}
AFTER['tokens']['2'] = {'type': 'systemd-fido2', 'keyslots': ['2']}


class LuksSetupTests(unittest.TestCase):
    @patch.object(luks, 'wait_for_key')
    @patch.object(luks, 'metadata', side_effect=[BEFORE, AFTER])
    @patch.object(luks, 'run')
    def test_enroll_tests_only_new_token_without_mapping(self, run, *_):
        luks.enroll_key(DEVICE)
        self.assertEqual(run.call_args_list[0].args,
                         ('systemd-cryptenroll', DEVICE, '--fido2-device=auto',
                          '--fido2-with-client-pin=yes', '--fido2-with-user-presence=yes'))
        self.assertEqual(run.call_args_list[1].args,
                         ('cryptsetup', 'open', '--test-passphrase', '--token-only', '--token-id', '2', DEVICE))

    def test_refuses_changed_existing_slot_token_or_volume(self):
        variants = []
        for section, key in [('keyslots', '0'), ('tokens', '1'), ('segments', '0')]:
            changed = copy.deepcopy(AFTER)
            del changed[section][key]
            variants.append(changed)
        for changed in variants:
            with self.subTest(section=changed), patch.object(luks, 'wait_for_key'), \
                    patch.object(luks, 'metadata', side_effect=[BEFORE, changed]), \
                    patch.object(luks, 'run') as run:
                with self.assertRaises(RuntimeError):
                    luks.enroll_key(DEVICE)
                self.assertEqual(run.call_count, 1)

    @patch.object(luks, 'wait_for_key')
    @patch.object(luks, 'metadata', side_effect=[BEFORE, BEFORE])
    @patch.object(luks, 'run')
    def test_refuses_to_mistake_existing_key_for_new_enrollment(self, run, *_):
        with self.assertRaises(RuntimeError):
            luks.enroll_key(DEVICE)
        self.assertEqual(run.call_count, 1)

    @patch('builtins.input', return_value='cancel')
    @patch.object(luks, 'run')
    @patch.object(luks, 'private_backup')
    def test_cancel_does_not_write_or_enroll(self, backup, run, *_):
        luks.enroll(DEVICE)
        run.assert_not_called()
        backup.assert_not_called()

    @patch('builtins.input', return_value='ENROLL')
    @patch.object(luks, 'run', side_effect=RuntimeError('passphrase failed'))
    @patch.object(luks, 'private_backup')
    @patch.object(luks, 'enroll_key')
    def test_password_failure_prevents_all_writes(self, enroll, backup, run, *_):
        with self.assertRaises(RuntimeError):
            luks.enroll(DEVICE)
        backup.assert_not_called()
        enroll.assert_not_called()
        self.assertIn('--disable-external-tokens', run.call_args.args)
        self.assertIn('--test-passphrase', run.call_args.args)

    @patch('builtins.input', return_value='ENROLL')
    @patch.object(luks, 'run')
    @patch.object(luks, 'private_backup', return_value=Path('/synthetic-backup'))
    @patch.object(luks, 'backup_header', side_effect=RuntimeError('backup failed'))
    @patch.object(luks, 'enroll_key')
    def test_backup_failure_prevents_enrollment(self, enroll, *_):
        with self.assertRaises(RuntimeError):
            luks.enroll(DEVICE)
        enroll.assert_not_called()

    @patch('builtins.input', return_value='ENROLL')
    @patch.object(luks, 'confirm', return_value=False)
    @patch.object(luks, 'run')
    @patch.object(luks, 'private_backup', return_value=Path('/synthetic-backup'))
    def test_before_backup_precedes_enrollment_and_final_backup_follows(self, *_):
        events = []
        with patch.object(luks, 'backup_header', side_effect=lambda _, p: events.append(p.name)), \
                patch.object(luks, 'enroll_key', side_effect=lambda _: events.append('enroll')):
            luks.enroll(DEVICE)
        self.assertEqual(events, ['header-before.img', 'enroll', 'header-after.img'])

    @patch('builtins.input', return_value='ENROLL')
    @patch.object(luks, 'run')
    @patch.object(luks, 'private_backup', return_value=Path('/synthetic-backup'))
    @patch.object(luks, 'enroll_key', side_effect=RuntimeError('token test failed'))
    @patch.object(luks, 'confirm')
    @patch.object(luks, 'backup_header')
    def test_key_failure_stops_before_recovery_or_final_backup(self, backup, confirm, *_):
        with self.assertRaises(RuntimeError):
            luks.enroll(DEVICE)
        confirm.assert_not_called()
        self.assertEqual(backup.call_count, 1)
        self.assertEqual(backup.call_args.args[1].name, 'header-before.img')

    @patch.object(luks, 'wait_for_key')
    @patch.object(luks, 'metadata', return_value=BEFORE)
    @patch.object(luks, 'run', side_effect=RuntimeError('enrollment failed'))
    def test_failed_enrollment_does_not_attempt_test_or_slot_removal(self, run, metadata, *_):
        with self.assertRaises(RuntimeError):
            luks.enroll_key(DEVICE)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(metadata.call_count, 1)
        self.assertFalse(any('wipe' in arg for arg in run.call_args.args))

    def test_private_backup_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'project/luks-backups'
            backup = luks.private_backup(base)
            for path in (base.parent, base, backup):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            linked = Path(directory) / 'linked'
            linked.symlink_to(base, target_is_directory=True)
            with self.assertRaises(ValueError):
                luks.private_backup(linked / 'nested')
            base.chmod(0o755)
            with self.assertRaises(ValueError):
                luks.private_backup(base)

    @patch.object(luks.subprocess, 'run')
    def test_failed_command_does_not_expose_captured_metadata(self, run):
        run.return_value = subprocess.CompletedProcess(['cryptsetup'], 1, 'synthetic-private-header', 'synthetic-private-error')
        with self.assertRaises(RuntimeError) as raised:
            luks.run('cryptsetup', 'luksDump', DEVICE, capture=True)
        self.assertNotIn('synthetic-private', str(raised.exception))
        self.assertNotIn(DEVICE, str(raised.exception))

    @patch.object(luks, 'preflight')
    @patch.object(luks, 'enroll')
    @patch.object(luks.os, 'geteuid', return_value=0)
    def test_check_is_read_only(self, _uid, enroll, preflight):
        with patch('sys.argv', ['enroll-luks.py', '--device', DEVICE, '--check']):
            luks.main()
        preflight.assert_called_once()
        enroll.assert_not_called()

    @patch.object(luks, 'run', side_effect=['', 'two-keys\nother-key\n', 'one-key\n'])
    @patch('builtins.input', return_value='')
    def test_waits_until_exactly_one_key(self, input_, run):
        luks.wait_for_key()
        self.assertEqual(input_.call_count, 3)


class HookConversionTests(unittest.TestCase):
    def convert(self, hooks, twice=False):
        script = 'HOOKS=(' + ' '.join(hooks) + ')\n'
        script += 'source "$1" || exit 1\n'
        if twice:
            script += 'source "$1" || exit 1\n'
        script += 'printf "%s\\n" "${HOOKS[@]}"\n'
        return subprocess.run(['bash', '--noprofile', '--norc', '-c', script, 'test',
                               str(ROOT / 'luks/zzzz-omarchy-yubikey-luks.conf')],
                              capture_output=True, text=True)

    def test_original_boot_path_conversion_snapshot_and_resume(self):
        result = self.convert('base udev plymouth keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems fsck btrfs-overlayfs resume'.split(), twice=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), 'base systemd plymouth keyboard autodetect microcode modconf kms sd-vconsole block sd-encrypt filesystems fsck sd-btrfs-overlayfs'.split())

    def test_keeps_hardware_kms_decision(self):
        result = self.convert('base udev keyboard autodetect modconf block encrypt filesystems fsck'.split())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('kms', result.stdout.split())

    def test_refuses_unknown_runtime_hook_and_missing_encryption(self):
        for hooks in ['base udev keyboard block encrypt custom-runtime filesystems',
                      'base udev keyboard block filesystems', 'base block encrypt filesystems']:
            with self.subTest(hooks=hooks):
                result = self.convert(hooks.split())
                self.assertNotEqual(result.returncode, 0)

    def test_refuses_bad_hook_order(self):
        for hooks in ['base udev encrypt block filesystems',
                      'base block encrypt udev filesystems',
                      'base udev block filesystems encrypt']:
            with self.subTest(hooks=hooks):
                result = self.convert(hooks.split())
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
