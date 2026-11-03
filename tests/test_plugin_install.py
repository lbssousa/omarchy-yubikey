from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PluginInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='yubikey-plugin-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config'
        self.state = self.root / 'state'
        binary = self.root / 'bin'
        binary.mkdir()
        validator = binary / 'omarchy'
        validator.write_text('#!/bin/sh\nexit 0\n')
        validator.chmod(0o755)
        self.env = dict(os.environ, XDG_CONFIG_HOME=str(self.config), XDG_STATE_HOME=str(self.state), PATH=str(binary) + os.pathsep + os.environ['PATH'])

    def run_install(self, *args):
        return subprocess.run(['bash', str(ROOT / 'scripts/install-plugins.sh'), *args], env=self.env, capture_output=True, text=True)

    def test_initial_install_and_default_refusal_to_overwrite(self):
        first = self.run_install()
        self.assertEqual(first.returncode, 0, first.stderr)
        plugin = self.config / 'omarchy/plugins/yubikey.lock'
        self.assertEqual((plugin / 'Service.qml').read_bytes(), (ROOT / 'plugins/yubikey.lock/Service.qml').read_bytes())
        (plugin / 'local-note').write_text('Existing user customization')
        second = self.run_install()
        self.assertNotEqual(second.returncode, 0)
        self.assertTrue((plugin / 'local-note').is_file())

    def test_update_keeps_previous_copy_in_private_backup(self):
        self.assertEqual(self.run_install().returncode, 0)
        plugin = self.config / 'omarchy/plugins/yubikey.lock'
        (plugin / 'local-note').write_text('Existing user customization')
        result = self.run_install('--update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((plugin / 'local-note').exists())
        saved = list(self.state.glob('omarchy-yubikey/backups/*/yubikey.lock/local-note'))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].read_text(), 'Existing user customization')
        self.assertEqual(saved[0].parent.parent.stat().st_mode & 0o777, 0o700)

    def test_preflight_rejects_symlink_before_copying_other_plugin(self):
        plugins = self.config / 'omarchy/plugins'
        plugins.mkdir(parents=True)
        (plugins / 'yubikey.lock').symlink_to(self.root / 'external')
        result = self.run_install('--update')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((plugins / 'yubikey.polkit').exists())
        self.assertFalse((self.root / 'external').exists())


if __name__ == '__main__':
    unittest.main()
