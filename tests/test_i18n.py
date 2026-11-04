import importlib.util
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('yubikey_i18n', ROOT / 'scripts/i18n.py')
i18n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i18n)


class TranslationTests(unittest.TestCase):
    def test_all_fifty_catalogs_have_identical_keys_and_placeholders(self):
        registry = json.loads((ROOT / 'i18n/locales.json').read_text())
        english = json.loads((ROOT / 'i18n/en.json').read_text())
        self.assertEqual(len(registry), 50)
        for code in registry:
            translated = json.loads((ROOT / 'i18n' / (code + '.json')).read_text())
            self.assertEqual(set(translated), set(english), code)
            for key, value in translated.items():
                with self.subTest(code=code, key=key):
                    self.assertIsInstance(value, str)
                    self.assertTrue(value.strip())
                    self.assertEqual(sorted(i18n.TOKEN.findall(key)), sorted(i18n.TOKEN.findall(value)))
                    self.assertNotRegex(value, r'ZXQ(?:MSG|END|T)')
                    if 'Type password' in key or 'literal word password' in key:
                        self.assertIn('password', value)
                    for literal in re.findall(r'https?://[^\s)]+|--[a-z][a-z0-9-]*|\b(?:ENROLL|IMPORT|FIDO2|PIN|YubiKey|GNOME Keyring)\b', key):
                        self.assertIn(literal, value)

    def test_generated_distributions_are_current(self):
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-i18n.py'), '--check'], check=True)

    def test_canonical_messages_used_in_source_are_present(self):
        english = json.loads((ROOT / 'i18n/en.json').read_text())
        for path in (ROOT / 'scripts').glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'tr' and node.args:
                    value = node.args[0]
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        self.assertIn(value.value, english, str(path))
        for path in (ROOT / 'keyring-unlock/src').glob('*.rs'):
            for value in re.findall(r'tr!\(\s*("(?:\\.|[^"\\])*")', path.read_text()):
                self.assertIn(json.loads(value), english, str(path))

    def test_standalone_exports_include_every_locale_and_hash_every_file(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([sys.executable, str(ROOT / 'scripts/export-plugins.py'), '--output', directory],
                           check=True, capture_output=True)
            registry = json.loads((ROOT / 'i18n/locales.json').read_text())
            for role in ['lock', 'polkit']:
                exported = Path(directory) / ('omarchy-yubikey-' + role)
                provenance = json.loads((exported / 'SOURCE.json').read_text())
                for code in registry:
                    self.assertIn('i18n/' + code + '.json', provenance['sha256'])
                for filename, digest in provenance['sha256'].items():
                    self.assertEqual(hashlib.sha256((exported / filename).read_bytes()).hexdigest(), digest)

    def test_regional_codes_and_unsafe_values(self):
        for value, expected in [('de_AT.UTF-8', 'de'), ('pt_BR.UTF-8', 'pt-BR'),
                                ('es_ES.UTF-8', 'es-MX'), ('nb_NO', 'no'), ('zh_HK', 'zh-TW'),
                                ('tl_PH', 'fil'), ('C.UTF-8', 'en'), ('../../de', 'en')]:
            self.assertEqual(i18n.normalize(value), expected)

    def test_placeholder_arguments_are_inserted_once(self):
        self.assertEqual(i18n.render('%2 / %1 / %10', ['%2', '<b>&data</b>']), '<b>&data</b> / %2 / %10')

    def test_partial_and_invalid_catalogs_fall_back_without_reinterpreting_values(self):
        with patch.object(i18n, 'catalog', side_effect=lambda code: {
                'locales': {'pt-BR': {}, 'pt': {}, 'en': {}},
                'pt-BR': {'Hello %1': 'Broken %2'}, 'pt': {'Hello %1': 'Olá %1'},
                'en': {'Hello %1': 'Hello %1'}}.get(code, {})):
            self.assertEqual(i18n.tr('Hello %1', '%2', code='pt-BR'), 'Olá %2')
            self.assertEqual(i18n.tr('New message %1', '%2', code='pt-BR'), 'New message %2')

    def test_language_is_per_account_and_explicit_override_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, code in [('first', 'de'), ('second', 'ja')]:
                config = Path(directory) / name
                (config / 'omarchy').mkdir(parents=True)
                (config / 'omarchy/language').write_text(code + '\n')
                environment = dict(os.environ, XDG_CONFIG_HOME=str(config),
                                   OMARCHY_YUBIKEY_LANGUAGE='', OMARCHY_LANGUAGE_FILE='')
                result = subprocess.check_output([sys.executable, str(ROOT / 'scripts/i18n.py'), '--language-code'], env=environment, text=True)
                self.assertEqual(result, code)
            with patch.object(sys, 'argv', ['test', '--language', 'fr']), patch.dict(os.environ, OMARCHY_YUBIKEY_LANGUAGE='de'):
                self.assertEqual(i18n.language(), 'fr')


if __name__ == '__main__':
    unittest.main()
