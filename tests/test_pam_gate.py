import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pam_setup', ROOT / 'scripts/configure-pam.py')
pam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pam)


class PamConversationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='isolated-pam-conversations-')
        cls.directory = Path(cls.temp.name)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.gate = cls.directory / 'gate.so'
        cls.fake = cls.directory / 'fake.so'
        cls.driver = cls.directory / 'driver'
        subprocess.run(['bash', str(ROOT / 'scripts/build-pam-gate.sh'), str(cls.gate)], check=True)
        subprocess.run(['cc', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                        str(ROOT / 'tests/pam_test_auth.c'), '-lpam', '-o', str(cls.fake)], check=True)
        subprocess.run(['cc', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'tests/pam_test_driver.c'), '-lpam', '-o', str(cls.driver)], check=True)

    def authenticate(self, answers, key='key', silent=False, gate=None, fallback='explicit', language='en'):
        standard = 'auth include system-auth\naccount include system-auth\n'
        config = pam.pam_with_key(standard, 'pin', fallback)
        config = config.replace('pam_u2f.so', str(self.fake) + ' ' + key)
        config = config.replace('/' + pam.GATE, str(gate or self.gate))
        (self.directory / 'isolated-test').write_text(config)
        (self.directory / 'system-auth').write_text(f'auth required {self.fake} password\n')
        return subprocess.run([str(self.driver), str(self.directory), '32768' if silent else '0', *answers],
                              capture_output=True, text=True, env=dict(os.environ, OMARCHY_YUBIKEY_LANGUAGE=language))

    def test_key_success_never_prompts_for_password(self):
        result = self.authenticate(['123456'])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('fallback', result.stdout)
        self.assertNotIn('Account password', result.stdout)

    def test_wrong_pin_cannot_be_reused_as_account_password(self):
        result = self.authenticate(['test-password'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fallback', result.stdout)
        self.assertNotIn('Account password', result.stdout)

    def test_only_literal_confirmation_reaches_password_stack(self):
        for answer in ('', 'yes', 'Password', 'test-password'):
            with self.subTest(answer=answer):
                result = self.authenticate([answer, 'test-password'], key='fail')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Account password', result.stdout)
        result = self.authenticate(['password', 'test-password'], key='fail')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('Account password', result.stdout)

    def test_confirmation_alone_is_not_authentication(self):
        self.assertNotEqual(self.authenticate(['password', 'wrong'], key='fail').returncode, 0)
        self.assertNotEqual(self.authenticate(['password'], key='fail').returncode, 0)

    def test_absent_gate_cancel_and_silent_fail_closed(self):
        self.assertNotEqual(self.authenticate([], key='fail').returncode, 0)
        result = self.authenticate(['password', 'test-password'], key='fail', gate=self.directory / 'missing.so')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Account password', result.stdout)
        self.assertNotEqual(self.authenticate(['password', 'test-password'], key='fail', silent=True).returncode, 0)

    def test_all_fifty_languages_preserve_the_literal_confirmation_protocol(self):
        registry = json.loads((ROOT / 'i18n/locales.json').read_text())
        for code in registry:
            with self.subTest(language=code):
                result = self.authenticate(['password', 'test-password'], key='fail', language=code)
                self.assertEqual(result.returncode, 0, result.stdout)
                catalog = json.loads((ROOT / 'i18n' / (code + '.json')).read_text())
                self.assertIn(catalog['Use password fallback? Type password to continue: '].strip(), result.stdout)
        self.assertNotEqual(self.authenticate(['Passwort', 'test-password'], key='fail', language='de').returncode, 0)

    def test_automatic_legacy_policy_still_requires_real_password(self):
        self.assertEqual(self.authenticate(['test-password'], key='fail', fallback='automatic').returncode, 0)
        self.assertNotEqual(self.authenticate(['wrong'], key='fail', fallback='automatic').returncode, 0)
