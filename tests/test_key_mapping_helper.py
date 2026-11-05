"""The pkexec key helper changes only the caller's own line, in a synthetic root."""
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import pwd
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('key_mapping_helper', str(ROOT / 'scripts/key-mapping-helper'))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)
pam = helper.load_pam(ROOT / 'scripts')

OTHER = 'other_user:other-handle,other-key,es256,+presence+pin'


class KeyMappingHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.mapping = self.root / 'etc/fido2/fido2'
        self.mapping.parent.mkdir(parents=True)
        self.mapping.write_text(OTHER + '\n' + self.user + ':first-handle,first-key,es256,+presence+pin\n')

    def call(self, *argv, stdin=''):
        return helper.run(pam, self.root, self.user, list(argv), io.StringIO(stdin))

    def lines(self):
        return self.mapping.read_text().splitlines()

    def test_account_comes_only_from_pkexec(self):
        self.assertEqual(helper.account({'PKEXEC_UID': str(os.getuid())}), self.user)
        for environ in ({}, {'PKEXEC_UID': ''}, {'PKEXEC_UID': '1000; id'}, {'USER': 'other_user'}):
            with self.assertRaises(ValueError):
                helper.account(environ)
        with self.assertRaises(ValueError):
            helper.account({'PKEXEC_UID': '0'})

    def test_add_merges_the_callers_line_and_keeps_others(self):
        self.call('add', stdin=self.user + ':second-handle,second-key,es256,+presence+pin\n')
        lines = self.lines()
        self.assertIn(OTHER, lines)
        mine = [line for line in lines if line.startswith(self.user + ':')]
        self.assertEqual(mine, [self.user + ':first-handle,first-key,es256,+presence+pin:second-handle,second-key,es256,+presence+pin'])
        self.assertTrue(any((self.root / 'var/lib/omarchy-yubikey/backups').iterdir()))

    def test_add_refuses_another_accounts_enrollment(self):
        before = self.mapping.read_text()
        with self.assertRaises(ValueError):
            self.call('add', stdin='other_user:injected-handle,injected-key\n')
        with self.assertRaises(ValueError):
            self.call('add', stdin=self.user + ':new-handle,new-key\nother_user:injected-handle,injected-key\n')
        self.assertEqual(self.mapping.read_text(), before)

    def test_rejects_unexpected_arguments(self):
        for argv in (('add', '--user', 'other_user'), ('remove',), ('remove', 'f' * 63), ('remove', 'F' * 64), ('rollback', 'x'), ()):
            with self.assertRaises(ValueError):
                self.call(*argv)

    def test_remove_keeps_the_last_key_and_others(self):
        reference = pam.key_references(self.mapping.read_text(), self.user)[0]
        with self.assertRaises(ValueError):
            self.call('remove', reference)
        self.call('add', stdin=self.user + ':second-handle,second-key,es256,+presence+pin\n')
        self.call('remove', reference)
        self.assertIn(self.user + ':second-handle,second-key,es256,+presence+pin', self.lines())
        self.assertIn(OTHER, self.lines())
        other = pam.key_references(self.mapping.read_text(), 'other_user')[0]
        with self.assertRaises(ValueError):
            self.call('remove', other)

    def test_refuses_code_that_is_not_root_owned(self):
        if os.geteuid() == 0:
            self.skipTest('needs a non-root test account')
        with self.assertRaises(ValueError):
            helper.trusted_directory(ROOT / 'scripts')


if __name__ == '__main__':
    unittest.main()
