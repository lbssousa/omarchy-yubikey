import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

control = module('control_center', 'scripts/control-center.py')
pam = module('control_pam', 'scripts/configure-pam.py')


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_status_contains_only_metadata_and_does_not_create_state(self):
        mapping = self.root / 'etc/fido2/fido2'
        mapping.parent.mkdir(parents=True)
        mapping.write_text('example_user:private-handle,private-public-key:backup-handle,backup-public-key\nother_user:other-handle,other-key\n')
        store = self.root / 'encrypted-store'
        store.write_text(json.dumps({'version': 1, 'entries': [{'credential_id': 'private-credential', 'ciphertext': 'private-ciphertext', 'label': 'private-label'}]}))
        state = self.root / 'state'
        result = control.status(self.root, self.root / 'config', state, store, 'example_user', query=False)
        self.assertEqual(result['enrollment']['count'], 2)
        self.assertEqual(result['keyring']['count'], 1)
        rendered = json.dumps(result)
        for value in ('private-', 'other-handle', 'example_user', str(self.root)):
            self.assertNotIn(value, rendered)
        self.assertFalse(state.exists())

    def test_status_rejects_duplicate_account_and_invalid_stores(self):
        with self.assertRaises(ValueError):
            control.enrolled_count('user:one\nuser:two\n', 'user')
        store = self.root / 'store'
        store.write_text('[]')
        result = control.status(self.root, self.root / 'config', self.root / 'state', store, 'user', query=False)
        self.assertEqual(result['keyring']['state'], 'unreadable')

    def test_ui_catalogs_cover_every_literal_and_preserve_placeholders(self):
        import re
        english = json.loads((ROOT / 'i18n/control/en.json').read_text())
        german = json.loads((ROOT / 'i18n/control/de.json').read_text())
        self.assertEqual(set(english), set(german))
        for key, value in german.items():
            self.assertEqual(re.findall(r'%[0-9]+', key), re.findall(r'%[0-9]+', value))
        for path in (ROOT / 'ui').glob('*.qml'):
            for value in re.findall(r'strings\.t\(("(?:[^"\\]|\\.)*")', path.read_text()):
                self.assertIn(json.loads(value), english)

    def test_actions_are_fixed_argument_vectors(self):
        self.assertEqual(control.command_plan('setup-sudo')[0][-2:], ['--components', 'sudo'])
        self.assertEqual(control.command_plan('test-sudo'), [['sudo', '-k'], ['sudo', 'true']])
        self.assertEqual(control.command_plan('luks-check', '/dev/disk/by-id/example')[0][-3:], ['--device', '/dev/disk/by-id/example', '--check'])
        self.assertEqual(control.command_plan('rollback', backup='20261104-120000-abcdef01')[0][-2:], ['--rollback', '20261104-120000-abcdef01'])
        for action, device, backup in [('unknown', '', ''), ('setup', '/dev/example', ''), ('setup', '', 'example'), ('luks-enroll', '/dev/../etc/example', ''), ('luks-check', '/dev/example;touch x', ''), ('rollback', '', '../../example')]:
            with self.subTest(action=action, device=device, backup=backup), self.assertRaises(ValueError):
                control.command_plan(action, device, backup)

    def test_state_is_private_and_concurrent_operations_are_rejected(self):
        directory = control.private_directory(self.root / 'state')
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        with control.operation_lock(directory):
            with self.assertRaises(ValueError):
                with control.operation_lock(directory):
                    pass
        control.save_operation(directory, {'action': 'setup', 'phase': 'running', 'ticket': 'private-ticket'})
        self.assertEqual(control.operation_status(self.root / 'state'), {'action': 'setup', 'phase': 'interrupted'})
        self.assertNotIn('private-ticket', json.dumps(control.operation_status(self.root / 'state')))
        self.assertEqual((directory / 'operation.json').stat().st_mode & 0o777, 0o600)

    def test_symlinks_and_insecure_state_are_rejected(self):
        (self.root / 'link').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            control.private_directory(self.root / 'link/state')
        directory = control.private_directory(self.root / 'state')
        directory.chmod(0o755)
        with self.assertRaises(ValueError):
            control.private_directory(self.root / 'state')

    def test_terminal_failure_is_recorded_without_launch_details(self):
        with patch.object(control, 'paths', return_value=(self.root, self.root, self.root / 'state', self.root / 'store')), patch.object(control.os, 'geteuid', return_value=1000), patch.object(control.shutil, 'which', return_value='/usr/bin/example'), patch.object(control.subprocess, 'Popen', side_effect=OSError('private-launch-details')):
            with self.assertRaisesRegex(ValueError, '^Could not open an interactive terminal$'):
                control.launch('setup')
        self.assertEqual(control.operation_status(self.root / 'state')['phase'], 'failed')

    def test_terminal_cancel_never_executes_an_operation(self):
        import time
        ticket = 'a' * 32
        state = self.root / 'state'
        directory = control.private_directory(state)
        control.save_operation(directory, {'action': 'setup', 'phase': 'starting', 'ticket': ticket, 'time': time.time()})
        with contextlib.redirect_stdout(io.StringIO()), patch.object(control, 'paths', return_value=(self.root, self.root, state, self.root)), patch.object(control.os, 'geteuid', return_value=1000), patch.object(control.sys.stdin, 'isatty', return_value=True), patch.object(control.sys.stdout, 'isatty', return_value=True), patch('builtins.input', side_effect=['', '']), patch.object(control.subprocess, 'call') as execute:
            self.assertEqual(control.run('setup', ticket), 0)
            execute.assert_not_called()
        self.assertEqual(control.operation_status(state)['phase'], 'cancelled')

    def test_terminal_handoff_rejects_expired_or_wrong_tickets(self):
        state = self.root / 'state'
        directory = control.private_directory(state)
        control.save_operation(directory, {'action': 'setup', 'phase': 'starting', 'ticket': 'a' * 32, 'time': 0})
        with patch.object(control, 'paths', return_value=(self.root, self.root, state, self.root)), patch.object(control.os, 'geteuid', return_value=1000), patch.object(control.sys.stdin, 'isatty', return_value=True), patch.object(control.sys.stdout, 'isatty', return_value=True), patch.object(control.subprocess, 'call') as execute:
            with self.assertRaisesRegex(ValueError, 'expired'):
                control.run('setup', 'a' * 32)
            with self.assertRaisesRegex(ValueError, 'expired'):
                control.run('setup', 'b' * 32)
            execute.assert_not_called()

    def test_restore_handles_a_single_standalone_authentication_plugin(self):
        config = self.root / 'config'
        manifest = config / 'omarchy/plugins/yubikey.polkit/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('{"id":"yubikey.polkit"}')
        with patch.object(control, 'paths', return_value=(self.root, config, self.root, self.root)):
            self.assertEqual(control.command_plan('desktop-restore'), [['omarchy', 'plugin', 'disable', 'yubikey.polkit']])
            manifest.unlink()
            with self.assertRaisesRegex(ValueError, 'No included'):
                control.command_plan('desktop-restore')

    def test_keyring_service_requires_exact_reviewed_unit(self):
        config = self.root / 'config'
        unit = config / 'systemd/user/keyring-unlock.service'
        unit.parent.mkdir(parents=True)
        with patch.object(control, 'paths', return_value=(self.root, config, self.root, self.root)):
            unit.write_text('unreviewed service')
            with self.assertRaises(ValueError):
                control.command_plan('keyring-enable')
            unit.write_bytes((ROOT / 'systemd/keyring-unlock.service').read_bytes())
            self.assertEqual(control.command_plan('keyring-enable'), [['systemctl', '--user', 'enable', 'keyring-unlock.service']])


class EnrollmentManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mapping = self.root / 'etc/fido2/fido2'
        self.mapping.parent.mkdir(parents=True)
        self.original = 'other_user:other-handle,other-public\nexample_user:first-handle,first-public:second-handle,second-public\n'
        self.mapping.write_text(self.original)
        self.mapping.chmod(0o644)

    def test_add_preserves_existing_accounts_and_never_changes_pam_policy(self):
        changes = pam.plan(self.root, [], 'example_user:third-handle,third-public', 'example_user')
        self.assertEqual(set(changes), {'etc/fido2/fido2'})
        backup = pam.apply(self.root, changes)
        self.assertIn('other_user:other-handle,other-public', self.mapping.read_text())
        self.assertEqual(len(pam.key_references(self.mapping.read_text(), 'example_user')), 3)
        pam.restore(self.root, backup)
        self.assertEqual(self.mapping.read_text(), self.original)

    def test_remove_is_precise_preserves_other_users_and_can_be_rolled_back(self):
        selected = pam.key_references(self.original, 'example_user')[1]
        changes = pam.remove_key_plan(self.root, 'example_user', selected)
        self.assertEqual(set(changes), {'etc/fido2/fido2'})
        backup = pam.apply(self.root, changes)
        self.assertEqual(self.mapping.read_text(), 'other_user:other-handle,other-public\nexample_user:first-handle,first-public\n')
        with self.assertRaisesRegex(ValueError, 'last enrolled'):
            pam.remove_key_plan(self.root, 'example_user', pam.key_references(self.mapping.read_text(), 'example_user')[0])
        pam.restore(self.root, backup)
        self.assertEqual(self.mapping.read_text(), self.original)

    def test_missing_duplicate_and_insecure_registration_cannot_be_removed(self):
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            pam.remove_key_plan(self.root, 'example_user', '0' * 64)
        self.mapping.write_text('example_user:first-handle,first-public:first-handle,first-public\n')
        selected = pam.key_references(self.mapping.read_text(), 'example_user')[0]
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            pam.remove_key_plan(self.root, 'example_user', selected)
        self.mapping.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'root-controlled'):
            pam.remove_key_plan(self.root, 'example_user', selected)

    def test_malformed_mapping_cannot_leave_an_invalid_last_key(self):
        for mapping in ('example_user:first-handle,first-public:', 'example_user:first-handle,first-public:invalid', 'example_user:first-handle,first-public:bad handle,public'):
            self.mapping.write_text(mapping + '\n')
            with self.assertRaisesRegex(ValueError, 'malformed'):
                pam.key_references(mapping, 'example_user')

    def test_backup_listing_is_read_only_and_omits_enrollment_values(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pam.list_backups(self.root)
        self.assertFalse((self.root / 'var').exists())
        backup = pam.apply(self.root, pam.plan(self.root, [], 'example_user:third-handle,third-public', 'example_user'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pam.list_backups(self.root)
        self.assertIn(backup.name, output.getvalue())
        self.assertNotIn('handle', output.getvalue())
        self.assertIn('/etc/fido2/fido2', output.getvalue())


if __name__ == '__main__':
    unittest.main()
