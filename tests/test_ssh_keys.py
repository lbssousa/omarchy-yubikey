"""Resident SSH key copies in temporary directories; ssh-keygen is mocked."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_ssh', ROOT / 'scripts/manage-ssh.py')
ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh)


class SshKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.work.mkdir()
        self.target = self.base / 'ssh'
        patcher = patch.object(ssh, 'ssh_directory', return_value=self.target)
        patcher.start()
        self.addCleanup(patcher.stop)

    def download(self, *names):
        for name in names:
            (self.work / name).write_text('synthetic private ' + name)
            (self.work / (name + '.pub')).write_text('synthetic public ' + name)

    def test_lists_only_resident_private_key_files(self):
        self.target.mkdir()
        for name in ('id_ed25519_sk_rk', 'id_ed25519_sk_rk.pub', 'id_ecdsa_sk_rk_example', 'id_ed25519', 'id_ed25519_sk', 'notes'):
            (self.target / name).write_text('synthetic')
        (self.target / 'id_ecdsa_sk_rk_link').symlink_to(self.target / 'notes')
        self.assertEqual(ssh.resident_keys(self.target), ['id_ecdsa_sk_rk_example', 'id_ed25519_sk_rk'])
        self.assertEqual(ssh.status(), {'count': 2})
        self.assertEqual(ssh.resident_keys(self.base / 'missing'), [])

    def test_install_never_overwrites_and_sets_modes(self):
        self.download('id_ed25519_sk_rk', 'id_ecdsa_sk_rk_example')
        self.target.mkdir()
        (self.target / 'id_ecdsa_sk_rk_example.pub').write_text('existing')
        imported, skipped = ssh.install(self.work, self.target)
        self.assertEqual(imported, ['id_ed25519_sk_rk'])
        self.assertEqual(skipped, ['id_ecdsa_sk_rk_example'])
        self.assertEqual((self.target / 'id_ecdsa_sk_rk_example.pub').read_text(), 'existing')
        self.assertFalse((self.target / 'id_ecdsa_sk_rk_example').exists())
        self.assertEqual(stat.S_IMODE((self.target / 'id_ed25519_sk_rk').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.target / 'id_ed25519_sk_rk.pub').stat().st_mode), 0o644)

    def test_install_creates_a_private_ssh_directory(self):
        self.download('id_ed25519_sk_rk')
        ssh.install(self.work, self.target)
        self.assertTrue((self.target / 'id_ed25519_sk_rk').is_file())
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode) & 0o077, 0)

    def test_import_runs_ssh_keygen_in_a_private_directory(self):
        def call(command, cwd, timeout):
            self.assertEqual(command, ['ssh-keygen', '-K'])
            self.assertEqual(stat.S_IMODE(os.stat(cwd).st_mode), 0o700)
            (Path(cwd) / 'id_ed25519_sk_rk').write_text('synthetic private')
            (Path(cwd) / 'id_ed25519_sk_rk.pub').write_text('synthetic public')
            return 0
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.base)}), \
                patch.object(ssh.subprocess, 'call', side_effect=call), patch('builtins.print'):
            ssh.do_import()
        self.assertTrue((self.target / 'id_ed25519_sk_rk').is_file())
        self.assertEqual([p.name for p in self.base.iterdir() if p.name.startswith('omarchy-yubikey-ssh-')], [])

    def test_import_failure_without_keys_raises(self):
        with patch.object(ssh.subprocess, 'call', return_value=1), patch('builtins.print'):
            with self.assertRaises(ValueError):
                ssh.do_import()

    def test_remove_deletes_the_selected_pair_after_confirmation(self):
        self.target.mkdir()
        for name in ('id_ecdsa_sk_rk_example', 'id_ed25519_sk_rk'):
            (self.target / name).write_text('synthetic')
            (self.target / (name + '.pub')).write_text('synthetic')
        with patch('builtins.input', side_effect=['2', 'y']), patch('builtins.print'):
            ssh.do_remove()
        self.assertEqual(sorted(p.name for p in self.target.iterdir()), ['id_ecdsa_sk_rk_example', 'id_ecdsa_sk_rk_example.pub'])
        with patch('builtins.input', side_effect=['1', 'n']), patch('builtins.print'):
            ssh.do_remove()
        with patch('builtins.input', side_effect=['3']), patch('builtins.print'):
            with self.assertRaises(ValueError):
                ssh.do_remove()
        self.assertEqual(len(list(self.target.iterdir())), 2)


if __name__ == '__main__':
    unittest.main()
