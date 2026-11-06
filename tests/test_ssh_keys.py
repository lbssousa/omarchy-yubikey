"""Resident SSH key copies in temporary directories; ssh-keygen is mocked."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

AT = '@'  # keeps synthetic addresses out of the publication scan
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

    def resident(self, directory, name, application='ssh:'):
        directory.mkdir(exist_ok=True)
        (directory / name).write_text('synthetic private')
        (directory / (name + '.pub')).write_text('sk-ssh-ed25519' + AT + 'openssh.com AAAAsynthetic ' + application + '\n')

    def test_git_remote_recognizes_git_hosts_only(self):
        self.assertEqual(ssh.git_remote('ssh:github.com'), ('git', 'github.com', None))
        self.assertEqual(ssh.git_remote('ssh:GitLab.com'), ('git', 'gitlab.com', None))
        self.assertEqual(ssh.git_remote('ssh:bitbucket.org'), ('git', 'bitbucket.org', None))
        self.assertEqual(ssh.git_remote('ssh://forge' + AT + 'git.example.com:2222'), ('forge', 'git.example.com', '2222'))
        self.assertEqual(ssh.git_remote('ssh:gitea.example.net'), ('git', 'gitea.example.net', None))
        for value in (None, '', 'ssh:', 'github.com', 'ssh:alice', 'ssh:example.com', 'ssh:host.git',
                      'ssh:github.com:99999', 'ssh:github.com\nHost *', 'ssh:github.com IdentityAgent x'):
            self.assertIsNone(ssh.git_remote(value), value)

    def test_key_remote_reads_the_application_and_ignores_the_user_id(self):
        hexid = 'ab' * 32
        keys = {
            'id_ed25519_sk_rk': ('ssh:', None),
            'id_ed25519_sk_rk_git.example.org_' + hexid: ('ssh:git.example.org', ('git', 'git.example.org', None)),
            'id_ed25519_sk_rk_github.com': ('ssh:github.com', ('git', 'github.com', None)),
            'id_ed25519_sk_rk_github.com_alice': ('ssh:github.com', ('git', 'github.com', None)),
            'id_ed25519_sk_rk_git' + AT + 'github.com': ('ssh:', None),
            'id_ed25519_sk_rk_example.com_alice': ('ssh:example.com', None),
        }
        for name, (value, _) in keys.items():
            self.resident(self.target, name, value)
        for name, (_, remote) in keys.items():
            self.assertEqual(ssh.key_remote(self.target, name), remote, name)
        self.assertIsNone(ssh.key_remote(self.target, 'id_ed25519_sk_rk_missing'))

    def test_drop_in_uses_the_keys_without_the_agent(self):
        self.target.mkdir()
        names = ['id_ed25519_sk_rk_github.com', 'id_ed25519_sk_rk_github.com_alice']
        self.assertTrue(ssh.write_drop_in(self.target, names, ('git', 'github.com', None), 15))
        drop_in = self.target / 'config.d' / 'github.com.conf'
        self.assertEqual(drop_in.read_text(), (
            '# Created by omarchy-yubikey for resident SSH keys.\n'
            'Host github.com\n    User git\n'
            '    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com\n'
            '    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com_alice\n'
            '    IdentitiesOnly yes\n    IdentityAgent none\n'
            '    ControlMaster auto\n    ControlPath ~/.ssh/control/%C\n    ControlPersist 15m\n'))
        self.assertEqual(stat.S_IMODE(drop_in.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.target / 'control').stat().st_mode), 0o700)
        self.assertFalse(ssh.write_drop_in(self.target, ['other'], ('git', 'github.com', None), 0))
        self.assertIn('ControlPersist', drop_in.read_text())
        ssh.write_drop_in(self.target, ['id_ed25519_sk_rk_x'], ('forge', 'git.example.com', '2222'), 0)
        text = (self.target / 'config.d' / 'git.example.com.conf').read_text()
        self.assertIn('    User forge\n    Port 2222\n', text)
        self.assertNotIn('Control', text)

    def test_include_goes_on_top_and_keeps_the_config(self):
        self.target.mkdir()
        config = self.target / 'config'
        self.assertFalse(ssh.includes_drop_ins(config))
        ssh.add_include(config)
        self.assertEqual(config.read_text(), 'Include config.d/*.conf\n')
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        config.write_text('Host example\n    User alice\n')
        config.chmod(0o640)
        ssh.add_include(config)
        self.assertEqual(config.read_text(), 'Include config.d/*.conf\n\nHost example\n    User alice\n')
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertTrue(ssh.includes_drop_ins(config))
        config.write_text('  include ~/.ssh/config.d/*\n')
        self.assertTrue(ssh.includes_drop_ins(config))

    def test_import_offers_one_drop_in_per_git_host(self):
        def call(command, cwd, timeout):
            self.resident(Path(cwd), 'id_ed25519_sk_rk')
            self.resident(Path(cwd), 'id_ed25519_sk_rk_github.com', 'ssh:github.com')
            self.resident(Path(cwd), 'id_ed25519_sk_rk_github.com_alice', 'ssh:github.com')
            self.resident(Path(cwd), 'id_ed25519_sk_rk_git.example.org_' + 'cd' * 32, 'ssh:git.example.org')
            return 0
        # git.example.org: yes, 0 minutes; github.com: yes, default; Include: yes.
        with patch.object(ssh.subprocess, 'call', side_effect=call), patch('builtins.print'), \
                patch('builtins.input', side_effect=['y', '0', 'y', '', 'y']) as asked:
            ssh.do_import()
        self.assertEqual(asked.call_count, 5)
        github = (self.target / 'config.d' / 'github.com.conf').read_text()
        self.assertEqual(github.count('IdentityFile'), 2)
        self.assertIn('ControlPersist 15m', github)
        self.assertNotIn('Control', (self.target / 'config.d' / 'git.example.org.conf').read_text())
        self.assertEqual(sorted(p.name for p in (self.target / 'config.d').iterdir()),
                         ['git.example.org.conf', 'github.com.conf'])
        self.assertTrue(ssh.includes_drop_ins(self.target / 'config'))

    def test_import_offers_a_drop_in_for_a_kept_identical_copy(self):
        name = 'id_ed25519_sk_rk_github.com'
        self.resident(self.target, name, 'ssh:github.com')
        (self.target / 'config').write_text('Include config.d/*.conf\n')
        with patch.object(ssh.subprocess, 'call', side_effect=lambda command, cwd, timeout: self.resident(Path(cwd), name, 'ssh:github.com') or 0), \
                patch('builtins.print'), patch('builtins.input', side_effect=['y', '0']):
            ssh.do_import()
        self.assertNotIn('Control', (self.target / 'config.d' / 'github.com.conf').read_text())

    def test_minutes_are_bounded(self):
        for answer, minutes in (('', 15), ('0', 0), ('30', 30), ('1440', 1440)):
            with patch('builtins.input', return_value=answer):
                self.assertEqual(ssh.ask_minutes(), minutes)
        for answer in ('-1', '1441', '1.5', 'x'):
            with patch('builtins.input', return_value=answer), self.assertRaises(ValueError):
                ssh.ask_minutes()

    def test_remove_takes_the_key_out_of_its_drop_in(self):
        names = ['id_ed25519_sk_rk_github.com', 'id_ed25519_sk_rk_github.com_alice']
        for name in names:
            self.resident(self.target, name, 'ssh:github.com')
        ssh.write_drop_in(self.target, names, ('git', 'github.com', None), 15)
        drop_in = self.target / 'config.d' / 'github.com.conf'
        (self.target / 'config.d' / 'mine.conf').write_text('Host example\n    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com\n')
        with patch('builtins.input', side_effect=['2', 'y']), patch('builtins.print'):
            ssh.do_remove()
        self.assertEqual(drop_in.read_text().count('IdentityFile'), 1)
        self.assertNotIn('_alice', drop_in.read_text())
        self.assertEqual(stat.S_IMODE(drop_in.stat().st_mode), 0o600)
        with patch('builtins.input', side_effect=['1', 'y']), patch('builtins.print'):
            ssh.do_remove()
        self.assertEqual([p.name for p in (self.target / 'config.d').iterdir()], ['mine.conf'])
        self.assertFalse(any((self.target / name).exists() for name in names))

if __name__ == '__main__':
    unittest.main()
