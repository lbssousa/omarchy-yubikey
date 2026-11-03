import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pam_setup', Path(__file__).resolve().parents[1] / 'scripts/configure-pam.py')
pam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pam)

STANDARD = '#%PAM-1.0\nauth\tinclude\tsystem-auth\naccount include system-auth\nsession include system-auth\n'
ENROLLMENT = 'example_user:example-handle,example-public-key'


class PamSetupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='yubikey-pam-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write('etc/pam.d/sudo', STANDARD)
        self.write('usr/lib/pam.d/polkit-1', STANDARD)
        self.write('etc/pam.d/omarchy-lock-password', 'auth required pam_unix.so\n')

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def plan(self, services=None):
        return pam.plan(self.root, services or ['sudo', 'polkit-1', 'omarchy-lock-fido2'], ENROLLMENT, 'example_user', gate=b'\x7fELF-test-module')

    def test_preserves_fallback_and_non_auth_rules(self):
        result = pam.pam_with_key(STANDARD)
        self.assertEqual(result, STANDARD.replace('auth\tinclude', pam.key_auth() + '\n' + pam.GATE_AUTH + '\nauth\tinclude'))
        self.assertEqual(pam.pam_with_key(result), result)

    def test_upgrade_legacy_and_switch_policy_without_duplicate_rules(self):
        old = STANDARD.replace('auth\tinclude', pam.AUTH + '\nauth\tinclude')
        hardened = pam.pam_with_key(old)
        self.assertIn('pinverification=1 userpresence=1', hardened)
        self.assertEqual(hardened.count('pam_u2f.so'), 1)
        self.assertIn(pam.GATE_AUTH, hardened)
        touch = pam.pam_with_key(hardened, 'touch', 'automatic')
        self.assertNotIn('pinverification=', touch)
        self.assertNotIn(pam.GATE_AUTH, touch)
        self.assertIn('userpresence=1', touch)

    def test_explicit_policy_requires_gate_before_writing(self):
        with self.assertRaises(ValueError):
            pam.plan(self.root, ['sudo'], ENROLLMENT, 'example_user')
        self.assertEqual((self.root / 'etc/pam.d/sudo').read_text(), STANDARD)

    def test_refuses_custom_stack_before_writing(self):
        path = self.write('etc/pam.d/sudo', 'auth sufficient pam_permit.so\naccount include system-auth\n')
        before = path.read_bytes()
        with self.assertRaises(ValueError):
            self.plan()
        self.assertEqual(before, path.read_bytes())
        self.assertFalse((self.root / 'etc/fido2').exists())

    def test_merges_keys_without_losing_other_users(self):
        existing = 'another_user:other-handle,other-public-key\nexample_user:old-handle,old-public-key\n'
        merged = pam.merge_mapping(existing, ENROLLMENT, 'example_user')
        self.assertEqual(merged, existing.rstrip() + ':example-handle,example-public-key\n')
        self.assertEqual(pam.merge_mapping(merged, ENROLLMENT, 'example_user'), merged)

    def test_rejects_duplicate_or_wrong_user_mapping(self):
        with self.assertRaises(ValueError):
            pam.merge_mapping(ENROLLMENT + '\n' + ENROLLMENT, ENROLLMENT, 'example_user')
        with self.assertRaises(ValueError):
            pam.merge_mapping('', ENROLLMENT, 'another_user')

    def test_apply_and_rollback_restore_existing_and_remove_new_files(self):
        path = self.root / 'etc/pam.d/sudo'
        path.chmod(0o640)
        changes = self.plan()
        old_umask = os.umask(0o077)
        try:
            backup = pam.apply(self.root, changes)
        finally:
            os.umask(old_umask)
        self.assertEqual((self.root / 'etc/fido2').stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.plan(), {})
        self.assertEqual((self.root / 'etc/fido2/fido2').stat().st_mode & 0o777, 0o644)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        pam.restore(self.root, backup)
        self.assertEqual(path.read_text(), STANDARD)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.root / 'etc/pam.d/polkit-1').exists())
        self.assertFalse((self.root / 'etc/fido2/fido2').exists())
        self.assertFalse((self.root / pam.GATE).exists())

    def test_write_failure_rolls_back(self):
        write = pam.write_atomic
        failed = False
        def interrupted(path, data, mode):
            nonlocal failed
            if path == self.root / 'etc/fido2/fido2' and not failed:
                failed = True
                raise OSError('Simulated interrupted write')
            write(path, data, mode)
        with patch.object(pam, 'write_atomic', interrupted):
            with self.assertRaises(OSError):
                pam.apply(self.root, self.plan())
        self.assertEqual((self.root / 'etc/pam.d/sudo').read_text(), STANDARD)
        self.assertFalse((self.root / 'etc/pam.d/polkit-1').exists())

    def test_rejects_symlink_target_and_insecure_mapping(self):
        (self.root / 'etc/pam.d/sudo').unlink()
        (self.root / 'etc/pam.d/sudo').symlink_to(self.root / 'usr/lib/pam.d/polkit-1')
        with self.assertRaises(ValueError):
            self.plan()
        (self.root / 'etc/pam.d/sudo').unlink()
        self.write('etc/pam.d/sudo', STANDARD)
        self.write('etc/fido2/fido2', ENROLLMENT + '\n').chmod(0o666)
        with self.assertRaises(ValueError):
            self.plan()

    def test_key_only_lock_requires_password_service(self):
        (self.root / 'etc/pam.d/omarchy-lock-password').unlink()
        with self.assertRaises(ValueError):
            self.plan()


if __name__ == '__main__':
    unittest.main()
