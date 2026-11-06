"""Card fixtures plus isolated real GnuPG public-key import and deletion guards."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_openpgp', ROOT / 'scripts/manage-openpgp.py')
pgp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pgp)
FPR, SUB = 'A' * 40, 'B' * 40
SERIAL = 'D2760001240100000000000000000000'
CARD = ('Reader:Example Reader:AID:' + SERIAL + ':openpgp-card:\n'
        'name:Example:User:\nurl:https\\x3a//keys.example.org/example.asc:\n'
        'fpr:' + FPR + ':' + SUB + '::\n')


def record(kind, fingerprint, capabilities, token='', validity='u', expiry=''):
    fields = [kind, validity, '255', '22', fingerprint[-16:], '1700000000', expiry, '', 'u', '', '',
              capabilities, '', '', token, '', 'ed25519', '', '', '0']
    return ':'.join(fields) + ':\nfpr:::::::::' + fingerprint + ':\n'


PUBLIC = record('pub', FPR, 'scSCE') + record('sub', SUB, 'e')
SECRET = record('sec', FPR, 'scSCE', '+') + record('ssb', SUB, 'e', '+')
STUB = record('sec', FPR, 'scSCE', SERIAL) + record('ssb', SUB, 'e', SERIAL)
UID = 'uid:u::::1::' + 'C' * 40 + '::Synthetic User::::::::::0:\n'


def completed(code=0, stdout=''):
    return subprocess.CompletedProcess([], code, stdout, '')


def fake_gpg(public=PUBLIC, secret=STUB, card=CARD):
    def run(command, **options):
        args = command[1:]
        if args[:2] == ['--card-status', '--with-colons']:
            return completed(0 if card else 2, card)
        if args[:1] == ['--list-keys']:
            return completed(0 if public else 2, public)
        if args[:1] == ['--list-secret-keys']:
            return completed(0, secret)
        return completed()
    return run


class OpenPgpTests(unittest.TestCase):
    def test_card_slots_keep_their_roles_when_an_earlier_slot_is_empty(self):
        found = pgp.parse_card(CARD)
        self.assertEqual(found['slots'], {'sign': FPR, 'encrypt': SUB, 'authenticate': ''})
        self.assertEqual(found['serial'], SERIAL)
        found = pgp.parse_card(CARD.replace('fpr:' + FPR + ':' + SUB, 'fpr::' + SUB))
        self.assertEqual(found['slots']['sign'], '')
        self.assertEqual(found['slots']['encrypt'], SUB)
        self.assertIsNone(pgp.parse_card('Reader:Other:AID:000:piv-card:\n'))
        self.assertEqual(pgp.unescape_colons(r'J\xc3\xb6rg\x3aName'), 'Jörg:Name')

    def test_disk_secret_is_not_reported_as_a_card_link(self):
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg(secret=SECRET)):
            value = pgp.status()
        self.assertFalse(value['linked'])
        self.assertFalse(value['ready'])
        self.assertTrue(value['local'])
        self.assertEqual(value['slots']['sign']['location'], 'disk')

    def test_real_card_stubs_and_other_card_are_distinguished(self):
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg()):
            value = pgp.status()
        self.assertTrue(value['linked'])
        self.assertTrue(value['ready'])
        self.assertFalse(value['local'])
        for text in [STUB.replace(SERIAL, 'E' * 32), STUB.replace(SERIAL, '#')]:
            with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg(secret=text)):
                self.assertFalse(pgp.status()['linked'])

    def test_offline_primary_and_card_subkey_are_evaluated_per_slot(self):
        found = pgp.parse_card(CARD.replace('fpr:' + FPR + ':' + SUB, 'fpr::' + SUB))
        mixed = record('sec', FPR, 'scSCE', '#') + record('ssb', SUB, 'e', SERIAL)
        slots = pgp.slot_states(found, PUBLIC, mixed)
        self.assertFalse(slots['sign']['present'])
        self.assertTrue(slots['encrypt']['ready'])
        mixed = record('sec', FPR, 'scSCE', '+') + record('ssb', SUB, 'e', SERIAL)
        self.assertTrue(pgp.slot_states(found, PUBLIC, mixed)['encrypt']['ready'])
        self.assertTrue(pgp.secret_on_disk(mixed))

    def test_expired_revoked_disabled_and_expired_subkeys_are_not_ready(self):
        for public in [PUBLIC.replace('pub:u:', 'pub:r:', 1),
                       PUBLIC.replace('pub:u:', 'pub:e:', 1),
                       PUBLIC.replace('scSCE', 'scSCED'),
                       PUBLIC.replace('sub:u:', 'sub:r:', 1),
                       PUBLIC.replace(':1700000000:', ':1700000000:1', 1)]:
            with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg(public=public)):
                self.assertFalse(pgp.status()['ready'])
        summary = pgp.key_summary(PUBLIC + UID)
        self.assertEqual(summary['fingerprint'], FPR)
        self.assertEqual(summary['uid'], 'Synthetic User')
        self.assertEqual(summary['algorithm'], 'ed25519')

    def test_status_only_exposes_bounded_public_identity(self):
        hostile_uid = UID.replace('Synthetic User', 'X' * 300 + r'\x1b\x3cimg\x3e')
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg(public=PUBLIC + hostile_uid)):
            value = pgp.status()
        self.assertEqual(len(value['key']['uid']), 256)
        self.assertNotIn(SERIAL, repr(value))
        self.assertNotIn('keys.example', repr(value))
        self.assertNotIn('\x1b', repr(value))

    def test_remove_refuses_any_local_secret_and_rechecks_after_confirmation(self):
        found = pgp.parse_card(CARD)
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg(secret=SECRET)) as calls:
            with self.assertRaises(ValueError):
                pgp.do_remove(found)
        self.assertFalse(any('--delete-secret-and-public-keys' in call.args[0] for call in calls.call_args_list))
        with patch.object(pgp, 'key_state', side_effect=[(FPR, 'u', STUB), (FPR, 'u', SECRET)]), \
                patch('builtins.input', return_value='REMOVE ' + FPR[-8:]), patch('builtins.print'), \
                patch.object(pgp, 'gpg') as execute:
            with self.assertRaises(ValueError):
                pgp.do_remove(found)
        execute.assert_not_called()

    def test_remove_card_stubs_requires_exact_confirmation(self):
        found = pgp.parse_card(CARD)
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg()) as calls, \
                patch('builtins.input', return_value='REMOVE ' + FPR[-8:]), patch('builtins.print'):
            pgp.do_remove(found)
        self.assertIn(['gpg', '--batch', '--yes', '--delete-secret-and-public-keys', FPR],
                      [call.args[0] for call in calls.call_args_list])
        with patch.object(pgp.subprocess, 'run', side_effect=fake_gpg()) as calls, \
                patch('builtins.input', return_value='REMOVE'), patch('builtins.print'):
            pgp.do_remove(found)
        self.assertFalse(any('--batch' in call.args[0] for call in calls.call_args_list))

    def test_secret_query_failure_prevents_deletion(self):
        original = fake_gpg()
        def run(command, **kwargs):
            return completed(2) if '--list-secret-keys' in command else original(command, **kwargs)
        with patch.object(pgp.subprocess, 'run', side_effect=run) as calls, self.assertRaises(ValueError):
            pgp.do_remove(pgp.parse_card(CARD))
        self.assertFalse(any('--delete-keys' in call.args[0] for call in calls.call_args_list))

    def test_trust_is_explicit_and_independent_of_readiness(self):
        found = pgp.parse_card(CARD)
        with patch.object(pgp, 'key_state', return_value=(FPR, '-', STUB)), \
                patch('builtins.input', return_value='y'), patch('builtins.print'), \
                patch.object(pgp, 'gpg', return_value=completed()) as execute:
            pgp.do_trust(found)
        execute.assert_called_once_with('--import-ownertrust', stdin=FPR + ':6:\n')

    def test_only_keyserver_urls_are_carried_into_staging(self):
        listing = 'keyserver:16:0:servers:1:1::::"hkps%3a//keys.example.org,"https%3a//other.example.org:\n'
        with patch.object(pgp.subprocess, 'run', return_value=completed(stdout=listing)):
            self.assertEqual(pgp.configured_keyservers(), ['hkps://keys.example.org', 'https://other.example.org'])
        hostile = listing.replace('hkps%3a//keys.example.org', 'hkps%3a//keys.example.org%0ahomedir%20elsewhere')
        with patch.object(pgp.subprocess, 'run', return_value=completed(stdout=hostile)):
            self.assertEqual(pgp.configured_keyservers(), ['https://other.example.org'])


class RealGnuPgTests(unittest.TestCase):
    """No hardware or network; every GnuPG process gets an explicit throwaway home."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source, self.target = self.base / 'source', self.base / 'target'
        for directory in [self.source, self.target]:
            directory.mkdir(mode=0o700)
        self.env = patch.dict(os.environ, {'GNUPGHOME': str(self.target)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.stop_agents)
        self.real_run = subprocess.run
        for label in ['Synthetic Intended', 'Synthetic Other']:
            result = self.real_run(['gpg', '--homedir', str(self.source), '--batch', '--pinentry-mode', 'loopback',
                                    '--passphrase', '', '--quick-generate-key', label, 'ed25519', 'sign', '1d'],
                                   capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        listing = pgp.key_listing('Synthetic Intended', homedir=self.source)
        self.fingerprint = pgp.primary_key(listing)[0]
        self.public = listing
        self.export = pgp.gpg('--armor', '--export', homedir=self.source).stdout
        self.other_export = pgp.gpg('--armor', '--export', 'Synthetic Other', homedir=self.source).stdout
        self.found = {'holder': 'Synthetic', 'serial': SERIAL, 'url': 'https://keys.example.org/key.asc',
                      'fingerprints': [self.fingerprint], 'slots': {'sign': self.fingerprint, 'encrypt': '', 'authenticate': ''}}

    def stop_agents(self):
        for directory in [self.source, self.target]:
            self.real_run(['gpgconf', '--homedir', str(directory), '--kill', 'all'], capture_output=True)

    def staged_run(self, command, **options):
        if command[0] == 'gpg' and ('--fetch-keys' in command or '--recv-keys' in command):
            self.assertIn('--homedir', command)
            stage = command[command.index('--homedir') + 1]
            self.assertNotEqual(stage, str(self.target))
            return self.real_run(['gpg', '--homedir', stage, '--batch', '--import'],
                                 input=self.download, capture_output=True, text=True)
        if command[0] == 'gpg' and '--card-status' in command:
            return completed()
        if command[0] == 'gpg' and '--list-secret-keys' in command and '--homedir' not in command:
            return completed(stdout=record('sec', self.fingerprint, 'scSC', SERIAL))
        return self.real_run(command, **options)

    def test_import_selects_only_matching_certificate_from_multi_key_download(self):
        self.download = self.export
        with patch.object(pgp.subprocess, 'run', side_effect=self.staged_run), \
                patch.object(pgp, 'card', return_value=self.found), \
                patch('builtins.input', return_value='y'), patch('builtins.print'):
            pgp.do_import(self.found)
        result = pgp.gpg('--list-keys', '--with-colons')
        self.assertIn(self.fingerprint, result.stdout)
        self.assertNotIn('Synthetic Other', result.stdout)

    def test_wrong_key_with_successful_fetch_never_changes_target_keyring(self):
        self.download = self.other_export
        with patch.object(pgp.subprocess, 'run', side_effect=self.staged_run), \
                patch('builtins.input', return_value='y'), patch('builtins.print'), self.assertRaises(ValueError):
            pgp.do_import(self.found)
        self.assertNotIn('pub:', pgp.gpg('--list-keys', '--with-colons').stdout)

    def test_wrong_url_key_falls_back_to_matching_keyserver_certificate(self):
        sources = []
        def run(command, **options):
            if '--fetch-keys' in command:
                self.download = self.other_export
                sources.append('url')
            elif '--recv-keys' in command:
                self.download = self.export
                sources.append('keyserver')
            return self.staged_run(command, **options)
        with patch.object(pgp.subprocess, 'run', side_effect=run), \
                patch.object(pgp, 'card', return_value=self.found), \
                patch('builtins.input', return_value='y'), patch('builtins.print'):
            pgp.do_import(self.found)
        self.assertEqual(sources, ['url', 'keyserver'])
        self.assertNotIn('Synthetic Other', pgp.gpg('--list-keys', '--with-colons').stdout)

    def test_public_only_key_has_no_card_link_and_can_be_removed_without_secret_loss(self):
        exported = pgp.gpg('--armor', '--export', self.fingerprint, homedir=self.source)
        self.assertEqual(pgp.gpg('--import', stdin=exported.stdout).returncode, 0)
        other = pgp.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                        '--armor', '--export-secret-keys', 'Synthetic Other', homedir=self.source)
        self.assertEqual(pgp.gpg('--import', stdin=other.stdout).returncode, 0)
        self.assertEqual(pgp.key_state(self.fingerprint)[2].strip(), '')
        with patch.object(pgp, 'card', return_value=self.found):
            value = pgp.status()
        self.assertTrue(value['imported'])
        self.assertFalse(value['linked'])
        self.assertFalse(value['ready'])
        with patch('builtins.input', return_value='REMOVE ' + self.fingerprint[-8:]), patch('builtins.print'):
            pgp.do_remove(self.found)
        remaining = pgp.gpg('--list-keys', '--with-colons').stdout
        self.assertNotIn(self.fingerprint, remaining)
        self.assertIn('Synthetic Other', remaining)

    def test_real_local_secret_material_blocks_removal(self):
        secret = pgp.gpg('--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                         '--armor', '--export-secret-keys', self.fingerprint, homedir=self.source)
        self.assertEqual(pgp.gpg('--import', stdin=secret.stdout).returncode, 0)
        self.assertTrue(pgp.secret_on_disk(pgp.key_state(self.fingerprint)[2]))
        with patch('builtins.input') as ask, self.assertRaises(ValueError):
            pgp.do_remove(self.found)
        ask.assert_not_called()
        self.assertIn('sec:', pgp.gpg('--list-secret-keys', '--with-colons').stdout)


if __name__ == '__main__':
    unittest.main()
