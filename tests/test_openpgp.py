"""OpenPGP card import with synthetic gpg listings; gpg itself is mocked."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_openpgp', ROOT / 'scripts/manage-openpgp.py')
openpgp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(openpgp)

FPR = 'A' * 40
CARD = ('Reader:Example Reader 00 00:AID:D2760001240100000000000000000000:openpgp-card:\n'
        'version:0304:\nname:Example:User:\nurl:https\\x3a//keys.example.org/example.asc:\n'
        'fpr:' + FPR + '::' + 'B' * 40 + ':\n')
PUBLIC = 'pub:u:255:22:' + FPR[-16:] + ':1:::u:::scESC::::::23::0:\nfpr:::::::::' + FPR + ':\n'
STUB = 'sec:u:255:22:' + FPR[-16:] + ':1:::u:::scESC:::D2760001240100000000000000000000::ed25519:::0:\n'
SECRET = 'sec:u:255:22:' + FPR[-16:] + ':1:::u:::scESC:::+::ed25519:::0:\n'


def completed(code=0, stdout=''):
    return subprocess.CompletedProcess([], code, stdout, '')


def fake_gpg(public=PUBLIC, secret=STUB, card=CARD):
    def run(command, **options):
        arguments = command[1:]
        if arguments[:2] == ['--card-status', '--with-colons']:
            return completed(0 if card else 2, card)
        if arguments[:1] == ['--list-keys']:
            return completed(0 if public else 2, public)
        if arguments[:1] == ['--list-secret-keys']:
            return completed(0 if secret else 2, secret)
        return completed()
    return run


class OpenPgpTests(unittest.TestCase):
    def test_parses_the_card_and_ignores_other_readers(self):
        card = openpgp.parse_card(CARD)
        self.assertEqual(card['holder'], 'Example User')
        self.assertEqual(card['url'], 'https://keys.example.org/example.asc')
        self.assertEqual(card['fingerprints'], [FPR, 'B' * 40])
        self.assertIsNone(openpgp.parse_card('Reader:Example Reader:AID:000:piv-card:\n'))
        self.assertIsNone(openpgp.parse_card(''))

    def test_primary_key_and_trust(self):
        self.assertEqual(openpgp.primary_key(PUBLIC), (FPR, 'u'))
        self.assertEqual(openpgp.primary_key(''), ('', ''))

    def test_secret_on_disk_tells_stubs_from_secrets(self):
        self.assertFalse(openpgp.secret_on_disk(STUB))
        self.assertFalse(openpgp.secret_on_disk(STUB.replace('D2760001240100000000000000000000', '#')))
        self.assertTrue(openpgp.secret_on_disk(SECRET))
        self.assertTrue(openpgp.secret_on_disk(STUB + 'ssb:u:255:18:0000000000000000:1::::::e::::::cv25519:::0:\n'))

    def test_status_reports_flags_only(self):
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg()):
            value = openpgp.status()
        self.assertEqual(value, {'card': True, 'imported': True, 'linked': True, 'trusted': True})
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg(public='', secret='')):
            self.assertEqual(openpgp.status(), {'card': True, 'imported': False, 'linked': False, 'trusted': False})
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg(card='')):
            self.assertEqual(openpgp.status()['card'], False)
        with patch.object(openpgp.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(openpgp.status()['card'], False)

    def test_remove_refuses_a_secret_kept_on_disk(self):
        found = openpgp.parse_card(CARD)
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg(secret=SECRET)) as mocked:
            with self.assertRaises(ValueError):
                openpgp.do_remove(found)
        self.assertFalse(any('--delete-secret-and-public-keys' in call.args[0] or '--delete-keys' in call.args[0]
                             for call in mocked.call_args_list))

    def test_remove_deletes_stubs_and_public_key_after_confirmation(self):
        found = openpgp.parse_card(CARD)
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg()) as mocked, \
                patch('builtins.input', return_value='REMOVE ' + FPR[-8:]), patch('builtins.print'):
            openpgp.do_remove(found)
        self.assertIn(['gpg', '--batch', '--yes', '--delete-secret-and-public-keys', FPR],
                      [call.args[0] for call in mocked.call_args_list])
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg()) as mocked, \
                patch('builtins.input', return_value='REMOVE'), patch('builtins.print'):
            openpgp.do_remove(found)
        self.assertFalse(any('--batch' in call.args[0] for call in mocked.call_args_list))

    def test_trust_imports_ownertrust_for_the_primary_key(self):
        found = openpgp.parse_card(CARD)
        untrusted = PUBLIC.replace(':::u:::', ':::-:::')
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg(public=untrusted)) as mocked, \
                patch('builtins.input', return_value='y'), patch('builtins.print'):
            openpgp.do_trust(found)
        calls = [call for call in mocked.call_args_list if '--import-ownertrust' in call.args[0]]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs['input'], FPR + ':6:\n')

    def test_import_tries_the_card_url_then_the_keyservers(self):
        found = openpgp.parse_card(CARD)
        called = []
        def call(command, **options):
            called.append(command)
            return 1 if '--fetch-keys' in command else 0
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg()), \
                patch.object(openpgp.subprocess, 'call', side_effect=call), \
                patch('builtins.input', return_value='y'), patch('builtins.print'):
            openpgp.do_import(found)
        self.assertEqual(called, [['gpg', '--fetch-keys', 'https://keys.example.org/example.asc'], ['gpg', '--recv-keys', FPR]])

    def test_import_ignores_a_card_url_that_is_not_a_key_location(self):
        found = dict(openpgp.parse_card(CARD), url='file:///etc/shadow')
        with patch.object(openpgp.subprocess, 'run', side_effect=fake_gpg()), \
                patch.object(openpgp.subprocess, 'call', return_value=0) as call, \
                patch('builtins.input', return_value='y'), patch('builtins.print'):
            openpgp.do_import(found)
        self.assertEqual([c.args[0] for c in call.call_args_list], [['gpg', '--recv-keys', FPR]])


if __name__ == '__main__':
    unittest.main()
