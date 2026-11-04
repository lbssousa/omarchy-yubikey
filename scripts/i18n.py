#!/usr/bin/env python3
"""Local catalog lookup; no network access or authentication decisions."""
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import sys

DIRECTORY = Path(__file__).resolve().parents[1] / 'i18n'
TOKEN = re.compile(r'%([1-9][0-9]*)')


@lru_cache(maxsize=64)
def catalog(code):
    try:
        value = json.loads((DIRECTORY / (code + '.json')).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def normalize(value):
    code = str(value).strip().split(':')[0].split('.')[0].split('@')[0].replace('_', '-')
    registry = catalog('locales')
    for known in registry:
        if known.lower() == code.lower():
            return known
    aliases = {'es': 'es-MX', 'nb': 'no', 'nn': 'no', 'tl': 'fil', 'zh': 'zh-CN',
               'zh-hk': 'zh-TW', 'zh-hant': 'zh-TW', 'zh-hans': 'zh-CN'}
    base = code.lower().split('-')[0]
    return aliases.get(code.lower(), aliases.get(base, base if base in registry else 'en'))


def language():
    # Resolve inside each process, never from a machine-wide preference. Explicit
    # arguments also survive sudo without preserving the desktop environment.
    for index, value in enumerate(sys.argv[1:], 1):
        if value.startswith('--language='):
            return normalize(value.split('=', 1)[1])
        if value == '--language' and index + 1 < len(sys.argv):
            return normalize(sys.argv[index + 1])
    if os.environ.get('OMARCHY_YUBIKEY_LANGUAGE'):
        return normalize(os.environ['OMARCHY_YUBIKEY_LANGUAGE'])
    config = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    path = Path(os.environ.get('OMARCHY_LANGUAGE_FILE') or config / 'omarchy/language')
    try:
        selected = path.read_text().strip()
        if selected:
            return normalize(selected)
    except OSError:
        pass
    for name in ('LC_ALL', 'LC_MESSAGES', 'LANGUAGE', 'LANG'):
        if os.environ.get(name):
            return normalize(os.environ[name])
    return 'en'


def render(template, values):
    # One pass: an account/path containing a token must not be substituted again.
    return TOKEN.sub(lambda match: str(values[int(match[1]) - 1])
                     if int(match[1]) <= len(values) else match[0], template)


def tr(source, *values, code=None):
    code = normalize(code) if code else language()
    for candidate in dict.fromkeys([code, code.split('-')[0], 'en']):
        value = catalog(candidate).get(source)
        if isinstance(value, str) and value and sorted(TOKEN.findall(value)) == sorted(TOKEN.findall(source)):
            return render(value, values)
    return render(source, values)


if __name__ == '__main__':
    if sys.argv[1:] == ['--language-code']:
        print(language(), end='')
    elif len(sys.argv) > 1:
        print(tr(sys.argv[1], *sys.argv[2:]), end='')
