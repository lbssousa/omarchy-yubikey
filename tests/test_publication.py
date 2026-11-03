import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('publication', Path(__file__).resolve().parents[1] / 'scripts/check-publication.py')
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def test_disk_identifier_is_rejected_without_echoing_value(self):
        value = b'12345678' + b'-1234-4234-8234-' + b'123456789abc'
        reasons = publication.content_failures(b'UUID=' + value)
        self.assertIn('non-synthetic UUID', reasons)
        self.assertTrue(all(value.decode() not in reason for reason in reasons))

    def test_only_explicit_synthetic_uuid_is_allowed(self):
        self.assertEqual(publication.content_failures(publication.SYNTHETIC_UUID), [])

    def test_boot_and_chat_artifacts_are_denied(self):
        for suffix in ('.img', '.efi', '.cpio', '.initramfs', '.jsonl'):
            self.assertIn(suffix, publication.DENIED_SUFFIXES)
        self.assertIn('crypttab.initramfs', publication.DENIED_NAMES)
        self.assertIn('machine-id', publication.DENIED_NAMES)


if __name__ == '__main__':
    unittest.main()
