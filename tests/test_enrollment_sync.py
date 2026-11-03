import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sync_enrollment', ROOT / 'scripts/sync-enrollment.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def credential(label):
    return ','.join([base64.b64encode(('handle-' + label).encode()).decode(),
                     base64.b64encode(('public-' + label).encode()).decode(), 'es256', '+presence+pin'])


class EnrollmentSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='enrollment-sync-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / 'root'
        self.root.mkdir()
        self.key = self.directory / 'signer'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-test', '-f', str(self.key)], check=True)
        trust = self.root / sync.TRUST
        trust.parent.mkdir(parents=True)
        trust.write_text('omarchy-yubikey:example_user ' + self.key.with_suffix('.pub').read_text())
        trust.chmod(0o644)
        self.mapping = self.root / sync.MAPPING
        self.mapping.write_text('another_user:' + credential('other') + '\nexample_user:' + credential('old') + '\n')
        self.mapping.chmod(0o644)

    def bundle(self, revision=1, credentials=None, user='example_user', origin=sync.ORIGIN):
        raw = (json.dumps({'schema': 1, 'origin': origin, 'user': user, 'revision': revision,
                           'credentials': [credential('new')] if credentials is None else credentials}) + '\n').encode()
        file = self.directory / 'bundle'
        file.write_bytes(raw)
        file.with_suffix('.sig').unlink(missing_ok=True)
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', sync.NAMESPACE, str(file)],
                       check=True, capture_output=True)
        return raw, file.with_suffix('.sig').read_bytes()

    def plan(self, raw, signature, minimum=1):
        return sync.import_plan(self.root, raw, signature, 'example_user', minimum)

    def test_real_signature_import_replaces_selected_user_and_preserves_others(self):
        raw, signature = self.bundle()
        before = self.mapping.read_bytes()
        bundle, old, changes = self.plan(raw, signature)
        self.assertEqual(old, [credential('old')])
        self.assertEqual(before, self.mapping.read_bytes())  # Preview writes nothing.
        sync.pam.apply(self.root, changes)
        self.assertEqual(sync.credentials_for(self.mapping.read_text(), 'example_user'), bundle['credentials'])
        self.assertEqual(sync.credentials_for(self.mapping.read_text(), 'another_user'), [credential('other')])
        self.assertEqual((self.root / sync.STATE).stat().st_mode & 0o777, 0o600)

    def test_tampered_payload_wrong_signer_wrong_principal_and_namespace_are_rejected(self):
        raw, signature = self.bundle()
        for changed_raw, changed_sig in ((raw.replace(b'"revision": 1', b'"revision": 2'), signature),
                                         (raw, signature.replace(b'SSH', b'BAD', 1))):
            with self.assertRaises(ValueError):
                self.plan(changed_raw, changed_sig)
        trust = self.root / sync.TRUST
        trust.write_text(trust.read_text().replace('example_user', 'another_user'))
        with self.assertRaises(ValueError):
            self.plan(raw, signature)

    def test_wrong_signing_key_and_signature_namespace_are_rejected(self):
        raw, signature = self.bundle()
        other = self.directory / 'untrusted-signer'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-test', '-f', str(other)], check=True)
        trust = self.root / sync.TRUST
        trust.write_text('omarchy-yubikey:example_user ' + other.with_suffix('.pub').read_text())
        with self.assertRaises(ValueError):
            self.plan(raw, signature)
        trust.write_text('omarchy-yubikey:example_user ' + self.key.with_suffix('.pub').read_text())
        file = self.directory / 'bundle'
        file.with_suffix('.sig').unlink()
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', 'unrelated-namespace', str(file)],
                       check=True, capture_output=True)
        with self.assertRaises(ValueError):
            self.plan(raw, file.with_suffix('.sig').read_bytes())

    def test_replay_and_old_versions_are_rejected_including_after_manual_rollback(self):
        raw, signature = self.bundle(3)
        backup = sync.pam.apply(self.root, self.plan(raw, signature, minimum=3)[2])
        for revision in (1, 2, 3):
            with self.assertRaises(ValueError):
                self.plan(*self.bundle(revision))
        sync.pam.restore(self.root, backup)
        self.assertEqual(sync.credentials_for(self.mapping.read_text(), 'example_user'), [credential('old')])
        with self.assertRaises(ValueError):
            self.plan(raw, signature)
        self.plan(*self.bundle(4))

    def test_first_import_needs_a_known_minimum_and_checks_account_and_origin(self):
        with self.assertRaises(ValueError):
            self.plan(*self.bundle(), minimum=None)
        with self.assertRaises(ValueError):
            self.plan(*self.bundle(2), minimum=3)
        for args in ({'user': 'another_user'}, {'origin': 'pam://different'}):
            with self.assertRaises(ValueError):
                self.plan(*self.bundle(**args))

    def test_empty_snapshot_revokes_all_keys_for_selected_user(self):
        changes = self.plan(*self.bundle(credentials=[]))[2]
        sync.pam.apply(self.root, changes)
        self.assertEqual(sync.credentials_for(self.mapping.read_text(), 'example_user'), [])
        self.assertIn('another_user:', self.mapping.read_text())

    def test_untrusted_paths_symlinks_and_oversized_input_are_refused(self):
        raw, signature = self.bundle()
        trust = self.root / sync.TRUST
        trust.chmod(0o666)
        with self.assertRaises(ValueError):
            self.plan(raw, signature)
        trust.chmod(0o644)
        self.mapping.rename(self.mapping.with_suffix('.original'))
        self.mapping.symlink_to(self.mapping.with_suffix('.original'))
        with self.assertRaises(ValueError):
            self.plan(raw, signature)
        file = self.directory / 'oversized'
        file.write_bytes(b'x' * (sync.LIMIT + 1))
        with self.assertRaises(ValueError):
            sync.read_regular(file)

    def test_schema_and_credential_injection_are_rejected(self):
        for credentials in ([credential('new') + '\nroot:bad'], ['*,abc,es256,+presence'],
                            [credential('new').replace('+presence', '')],
                            [credential('new'), credential('new')], ['bad,abc,unknown,+presence']):
            with self.subTest(credentials=credentials), self.assertRaises(ValueError):
                self.plan(*self.bundle(credentials=credentials))

    def test_failed_import_restores_mapping_and_watermark_as_one_transaction(self):
        raw, signature = self.bundle()
        changes = self.plan(raw, signature)[2]
        old = self.mapping.read_bytes()
        write = sync.pam.write_atomic
        failed = False
        def interrupted(path, data, mode):
            nonlocal failed
            if path == self.mapping and not failed:
                failed = True
                raise OSError('Synthetic failure')
            write(path, data, mode)
        with patch.object(sync.pam, 'write_atomic', interrupted), self.assertRaises(OSError):
            sync.pam.apply(self.root, changes)
        self.assertEqual(old, self.mapping.read_bytes())
        self.assertFalse((self.root / sync.STATE).exists())

    def test_export_into_separate_git_checkout_is_signed_private_and_not_overwritten(self):
        repo = self.directory / 'private-sync'
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        args = SimpleNamespace(repo=repo, mapping=self.mapping, user='example_user',
                               revision=2, signing_key=self.key)
        if os.geteuid() == 0:
            with self.assertRaises(ValueError):
                sync.export_bundle(args)
            return
        sync.export_bundle(args)
        file = repo / sync.FILENAME
        signature = Path(str(file) + '.sig')
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(signature.stat().st_mode & 0o777, 0o600)
        self.plan(file.read_bytes(), signature.read_bytes())
        with self.assertRaises(ValueError):
            sync.export_bundle(args)
