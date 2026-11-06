"""Resident-key operations and real OpenSSH configuration resolution in temp homes."""
import base64
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_ssh', ROOT / 'scripts/manage-ssh.py')
ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh)


def wire(value):
    return struct.pack('>I', len(value)) + value


def public(application='ssh:github.com', byte=1):
    algorithm = b'sk-ssh-ed25519' + b'@' + b'openssh.com'
    blob = wire(algorithm) + wire(bytes([byte]) * 32) + wire(application.encode())
    return algorithm.decode() + ' ' + base64.b64encode(blob).decode() + ' ignored-comment\n'


class SshKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.work.mkdir(mode=0o700)
        self.target = self.base / 'ssh'
        self.target.mkdir(mode=0o700)
        patcher = patch.object(ssh, 'ssh_directory', return_value=self.target)
        patcher.start()
        self.addCleanup(patcher.stop)

    def resident(self, directory, name, application='ssh:github.com', byte=1):
        pub = public(application, byte)
        blob = base64.b64decode(pub.split()[1])
        envelope = b'openssh-key-v1\0' + wire(b'none') + wire(b'none') + wire(b'') + struct.pack('>I', 1) + wire(blob) + wire(b'synthetic handle')
        (directory / name).write_text(ssh.PRIVATE_BEGIN + '\n' + base64.b64encode(envelope).decode() + '\n-----END-----\n')
        (directory / (name + '.pub')).write_text(pub)

    def configure(self, *names, minutes=0):
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': sorted(names), 'minutes': minutes}}
        ssh.private_directory(self.target / 'omarchy-yubikey')
        (self.target / ssh.MANAGED).write_text(ssh.managed_text(hosts))
        # Absolute path for ssh -G tests; production uses the user's ~/.ssh.
        (self.target / 'config').write_text(ssh.INCLUDE + '\n')
        return hosts

    def test_install_never_overwrites_either_half_and_sets_modes(self):
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        self.resident(self.work, 'id_ed25519_sk_rk_b', byte=2)
        (self.target / 'id_ed25519_sk_rk_b.pub').write_text('existing')
        imported, skipped = ssh.install(self.work, self.target)
        self.assertEqual(imported, ['id_ed25519_sk_rk_a'])
        self.assertEqual(skipped, ['id_ed25519_sk_rk_b'])
        self.assertEqual((self.target / 'id_ed25519_sk_rk_b.pub').read_text(), 'existing')
        for suffix, mode in [('', 0o600), ('.pub', 0o644)]:
            self.assertEqual(stat.S_IMODE((self.target / ('id_ed25519_sk_rk_a' + suffix)).stat().st_mode), mode)

    def test_install_requires_complete_public_pair_and_rolls_back_copy_error(self):
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        (self.work / 'id_ed25519_sk_rk_a.pub').unlink()
        with self.assertRaises(OSError):
            ssh.install(self.work, self.target)
        self.assertEqual(list(self.target.iterdir()), [])
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        original = ssh.copy_exclusive
        def copy(source, target, mode):
            if target.suffix == '.pub':
                raise OSError('synthetic disk full')
            original(source, target, mode)
        with patch.object(ssh, 'copy_exclusive', side_effect=copy), self.assertRaises(OSError):
            ssh.install(self.work, self.target)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_import_is_private_and_failed_partial_download_is_not_installed(self):
        name = 'id_ed25519_sk_rk_a'
        def call(command, cwd, timeout):
            self.assertEqual(command, ['ssh-keygen', '-K'])
            self.assertEqual(stat.S_IMODE(os.stat(cwd).st_mode), 0o700)
            self.resident(Path(cwd), name, 'ssh:')
            return 1
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.base)}), patch.object(ssh.subprocess, 'call', side_effect=call), patch('builtins.print'):
            with self.assertRaises(ValueError):
                ssh.do_import()
        self.assertFalse((self.target / name).exists())

    def test_application_is_taken_from_public_blob_not_mutable_comment(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        self.assertEqual(ssh.application(self.target, name), 'ssh:github.com')
        (self.target / (name + '.pub')).write_text(public().replace('ignored-comment', 'ssh:git.evil.example'))
        self.assertEqual(ssh.application(self.target, name), 'ssh:github.com')
        # OpenSSH independently accepts the synthetic public-key wire format.
        subprocess.run(['ssh-keygen', '-l', '-f', str(self.target / (name + '.pub'))],
                       check=True, capture_output=True)

    def test_mismatched_private_file_cannot_be_installed_or_deleted(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.work, name)
        (self.work / (name + '.pub')).write_text(public(byte=2))
        with self.assertRaises(ValueError):
            ssh.install(self.work, self.target)
        self.assertFalse((self.target / name).exists())
        self.resident(self.target, name)
        (self.target / name).write_text('unrelated software secret')
        self.assertEqual(ssh.status()['keys'], [])
        with patch('builtins.input') as ask, self.assertRaises(ValueError):
            ssh.do_remove(ssh.key_reference(self.target, name))
        ask.assert_not_called()

    def test_git_remote_is_allowlisted_and_validates_login_port(self):
        for value, expected in [('ssh:github.com', ('git', 'github.com', None)),
                                ('ssh://forge' + '@' + 'git.example.com:2222', ('forge', 'git.example.com', '2222'))]:
            self.assertEqual(ssh.git_remote(value), expected)
        for value in [None, 'ssh:', 'ssh:example.com', 'ssh:github.com:99999', 'ssh:github.com\nHost *',
                      'ssh:github.com IdentityAgent x']:
            self.assertIsNone(ssh.git_remote(value))

    def test_status_exposes_public_identity_and_no_filename(self):
        name = 'id_ed25519_sk_rk_private-user-id'
        self.resident(self.target, name)
        value = ssh.status()
        self.assertEqual(value['count'], 1)
        key = value['keys'][0]
        self.assertEqual(key['application'], 'ssh:github.com')
        self.assertEqual(key['type'], 'ed25519-sk')
        self.assertRegex(key['fingerprint'], r'^SHA256:[A-Za-z0-9+/]{43}$')
        self.assertRegex(key['id'], r'^[0-9a-f]{64}$')
        self.assertNotIn('private-user-id', repr(value))
        self.assertNotIn('synthetic private handle', repr(value))

    def test_real_openssh_passphrase_detection(self):
        for passphrase in ['', 'synthetic']:
            path = self.base / ('encrypted' if passphrase else 'plain')
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', passphrase, '-f', str(path)], check=True)
            self.assertEqual(ssh.has_passphrase(path), bool(passphrase))

    def test_symlinks_and_nonregular_files_are_not_read_or_replaced(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        (self.target / (name + '.pub')).unlink()
        (self.target / (name + '.pub')).symlink_to(self.base / 'elsewhere')
        self.assertEqual(ssh.status()['keys'], [])
        config = self.target / 'config'
        config.symlink_to(self.base / 'elsewhere')
        with self.assertRaises(OSError):
            ssh.config_text(self.target)
        fifo = self.target / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            ssh.read_file(fifo)

    def test_global_include_is_added_despite_conditional_include_and_preserves_text(self):
        original = 'Host internal.example\n    Include config.d/*.conf\n    User alice\n'
        result = ssh.include_text(original)
        self.assertTrue(result.startswith(ssh.INCLUDE + '\n'))
        self.assertIn(original, result)
        self.assertEqual(ssh.include_text(result), result)
        scoped = 'Host internal.example\n    ' + ssh.INCLUDE + '\n'
        self.assertEqual(ssh.include_text(scoped).count(ssh.INCLUDE), 1)

    def test_zero_reuse_overrides_inherited_multiplexing(self):
        name = 'id_ed25519_sk_rk_a'
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': [name], 'minutes': 0}}
        original = ('Host *\n    User original\n    IdentityAgent /synthetic-agent\n'
                    '    ControlMaster auto\n    ControlPath /synthetic-socket\n    ControlPersist 900\n')
        with patch('builtins.print'):
            ssh.preview(self.target, hosts, ssh.managed_text(hosts), original)
        text = ssh.drop_in_text([name], ('git', 'github.com', None), 0)
        config = self.base / 'resolved'
        config.write_text(text + original)
        options = ssh.ssh_options(config, 'github.com')
        self.assertIn('controlmaster false', options)
        self.assertFalse(any(line.startswith('controlpath ') for line in options))
        self.assertIn('controlpersist no', options)
        self.assertIn('identityagent none', options)
        self.assertIn('user git', options)
        self.assertIn('user original', ssh.ssh_options(config, 'unrelated.example'))

    def test_import_remove_reimport_restores_host_identity_line(self):
        a, b = 'id_ed25519_sk_rk_a', 'id_ed25519_sk_rk_b'
        for i, name in enumerate([a, b], 1):
            self.resident(self.target, name, byte=i)
        self.configure(a, b)
        reference = ssh.key_reference(self.target, a)
        with patch('builtins.input', side_effect=['y', 'y']), patch('builtins.print'):
            ssh.do_remove(reference)
        hosts, _, modified = ssh.load_managed(self.target)
        self.assertFalse(modified)
        self.assertEqual(hosts['github.com']['names'], [b])
        self.resident(self.target, a)
        with patch('builtins.input', side_effect=['y', 'y']), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [a, b])
        hosts, _, _ = ssh.load_managed(self.target)
        self.assertEqual(hosts['github.com']['names'], [a, b])

    def test_removal_reference_survives_reordering_and_rejects_replaced_public_key(self):
        selected = 'id_ed25519_sk_rk_z'
        self.resident(self.target, selected)
        reference = ssh.key_reference(self.target, selected)
        self.resident(self.target, 'id_ed25519_sk_rk_a', byte=2)
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            ssh.do_remove(reference)
        self.assertTrue((self.target / 'id_ed25519_sk_rk_a').exists())
        self.resident(self.target, selected, byte=3)
        with patch('builtins.input') as ask, self.assertRaises(ValueError):
            ssh.do_remove(reference)
        ask.assert_not_called()
        self.assertTrue((self.target / selected).exists())

    def test_key_changed_while_confirmation_is_open_is_not_deleted(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        reference = ssh.key_reference(self.target, name)
        def answer(_):
            (self.target / name).write_text('changed')
            return 'y'
        with patch('builtins.input', side_effect=answer), patch('builtins.print'), self.assertRaises(ValueError):
            ssh.do_remove(reference)
        self.assertEqual((self.target / name).read_text(), 'changed')

    def test_manually_edited_managed_file_requires_typed_replacement(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        hosts = self.configure(name)
        path = self.target / ssh.MANAGED
        path.write_text(path.read_text() + '# hand edit\n')
        _, previous, modified = ssh.load_managed(self.target)
        self.assertTrue(modified)
        self.assertTrue(ssh.status()['modified'])
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            self.assertFalse(ssh.save_hosts(self.target, hosts, previous, modified))
        self.assertIn('# hand edit', path.read_text())
        with patch('builtins.input', return_value='REPLACE'), patch('builtins.print'):
            self.assertTrue(ssh.save_hosts(self.target, hosts, previous, modified))
        self.assertFalse(ssh.load_managed(self.target)[2])

    def test_rejected_ssh_config_never_gets_written(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        (self.target / 'config').write_text('UnknownSyntheticDirective yes\n')
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': [name], 'minutes': 0}}
        with patch('builtins.input') as ask, patch('builtins.print'), self.assertRaises(ValueError):
            ssh.save_hosts(self.target, hosts, '')
        ask.assert_not_called()
        self.assertFalse((self.target / ssh.MANAGED).exists())
        self.assertEqual((self.target / 'config').read_text(), 'UnknownSyntheticDirective yes\n')

    def test_failed_include_write_can_be_finished_by_repeating_import(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        main = 'Host unrelated.example\n    User original\n'
        (self.target / 'config').write_text(main)
        original = ssh.replace_text
        def replace(path, *args, **kwargs):
            if path == self.target / 'config':
                raise OSError('synthetic interrupted write')
            return original(path, *args, **kwargs)
        with patch.object(ssh, 'replace_text', side_effect=replace), \
                patch('builtins.input', side_effect=['y', '0', 'y']), patch('builtins.print'), self.assertRaises(OSError):
            ssh.offer_drop_ins(self.target, [name])
        self.assertTrue((self.target / ssh.MANAGED).exists())
        self.assertEqual((self.target / 'config').read_text(), main)
        self.assertFalse(ssh.status()['keys'][0]['host'])
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [name])
        self.assertTrue((self.target / 'config').read_text().startswith(ssh.INCLUDE + '\n'))
        self.assertIn(main, (self.target / 'config').read_text())
        self.assertTrue(ssh.status()['keys'][0]['host'])

    def test_fresh_configuration_can_enable_reuse_and_preserves_main_mode(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        config = self.target / 'config'
        config.write_text('Host unrelated.example\n    User original\n')
        config.chmod(0o640)
        with patch('builtins.input', side_effect=['y', '15', 'y']), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [name])
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        hosts, text, modified = ssh.load_managed(self.target)
        self.assertEqual(hosts['github.com']['minutes'], 15)
        self.assertIn('ControlPersist 15m', text)
        self.assertFalse(modified)
        before = config.read_bytes(), (self.target / ssh.MANAGED).read_bytes()
        with patch('builtins.input') as ask:
            ssh.offer_drop_ins(self.target, [name])
        ask.assert_not_called()
        self.assertEqual(before, (config.read_bytes(), (self.target / ssh.MANAGED).read_bytes()))

    def test_minutes_default_to_no_reuse_and_are_bounded(self):
        for answer, expected in [('', 0), ('0', 0), ('15', 15), ('1440', 1440)]:
            with patch('builtins.input', return_value=answer):
                self.assertEqual(ssh.ask_minutes(), expected)
        for answer in ['-1', '1441', '0.1', 'x']:
            with patch('builtins.input', return_value=answer), self.assertRaises(ValueError):
                ssh.ask_minutes()

    def test_overlapping_operations_are_rejected(self):
        with ssh.operation_lock(self.target):
            with self.assertRaises(ValueError):
                with ssh.operation_lock(self.target):
                    pass


if __name__ == '__main__':
    unittest.main()
