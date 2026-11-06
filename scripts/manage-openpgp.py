#!/usr/bin/env python3
"""Bring the OpenPGP key stored on a security key into the account's GnuPG keyring.

Interactive terminal operations, run as the desktop user without privileges:

  import  fetch the public key from the URL stored on the card, or from the
          keyservers, and read the card so gpg links the key to it
  trust   mark that key as ultimately trusted (it is your own key)
  remove  take the key out of the keyring again: the public key and the stubs
          pointing at the card; the key itself stays on the card

Removal refuses whenever gpg keeps a secret part of the key on disk, which
would be lost for good. `status()` is the metadata-only probe used by the
control center: whether a card is present and the key imported, linked and
trusted, plus the imported key's algorithm, capabilities, expiry and number
of user IDs, without fingerprints, serials, names or addresses.
"""
import argparse
import datetime
import os
import re
import subprocess
import sys

PROBE_TIMEOUT = 5
NETWORK_TIMEOUT = 60
KEY_URL = re.compile(r'(?:https?|hkps?)://[^\s]+')
CURVES = {'ed25519', 'cv25519', 'ed448', 'cv448', 'nistp256', 'nistp384', 'nistp521',
          'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1'}
RSA = {'1', '2', '3'}


def unescape_colons(value):
    # gpg --with-colons escapes ':' and control characters as "\xHH".
    return re.sub(r'\\x([0-9A-Fa-f]{2})', lambda match: chr(int(match[1], 16)), value)


def parse_card(text):
    """`gpg --card-status --with-colons`; None without an OpenPGP card."""
    fields = {}
    for line in text.splitlines():
        parts = line.split(':')
        fields.setdefault(parts[0], parts[1:])
    reader = fields.get('Reader')
    if reader is None or 'openpgp-card' not in ':'.join(reader):
        return None

    def get(name, index):
        values = fields.get(name, [])
        return unescape_colons(values[index]) if index < len(values) else ''

    holder = ' '.join(part for part in (get('name', 0), get('name', 1)) if part)
    fingerprints = [value for value in fields.get('fpr', []) if re.fullmatch(r'[0-9A-Fa-f]{40,64}', value)]
    return {'holder': holder, 'url': get('url', 0), 'fingerprints': fingerprints}


def primary_key(text):
    """The primary fingerprint and ownertrust of `gpg --list-keys --with-colons`."""
    trust = ''
    for line in text.splitlines():
        parts = line.split(':')
        if parts[0] in ('pub', 'sec') and not trust:
            trust = parts[8] if len(parts) > 8 else ''
        elif parts[0] == 'fpr' and len(parts) > 9:
            return parts[9], trust
    return '', trust


def key_summary(text, now=None):
    """Non-identifying facts about the primary key of a --list-keys listing:
    algorithm, capabilities, expiry and how many user IDs it carries."""
    pub = next((line.split(':') for line in text.splitlines() if line.startswith('pub:')), None)
    if pub is None:
        return None
    pub += [''] * (17 - len(pub))
    if pub[16] in CURVES:
        algorithm = pub[16]
    elif pub[3] in RSA and pub[2].isdecimal() and 1024 <= int(pub[2]) <= 16384:
        algorithm = 'rsa' + pub[2]
    else:
        algorithm = 'other'
    expires, expired = '', pub[1] == 'e'
    if pub[6].isdecimal():
        moment = datetime.datetime.fromtimestamp(int(pub[6]), datetime.timezone.utc)
        expires = moment.strftime('%Y-%m-%d')
        expired = expired or moment < (now or datetime.datetime.now(datetime.timezone.utc))
    capabilities = pub[11]
    uids = sum(1 for line in text.splitlines() if line.startswith('uid:') and line.split(':')[1] != 'r')
    return {'algorithm': algorithm, 'sign': 'S' in capabilities, 'encrypt': 'E' in capabilities,
            'authenticate': 'A' in capabilities, 'expires': expires, 'expired': expired, 'uids': uids}


def secret_on_disk(colons):
    """Whether a --list-secret-keys --with-colons listing has a secret part kept
    in the keyring rather than on a card. Field 15 holds the card serial for a
    stub, "#" for a stub whose card is away, and "+" or nothing for a secret."""
    for line in colons.splitlines():
        fields = line.split(':')
        if fields[0] in ('sec', 'ssb') and (fields[14] if len(fields) > 14 else '') in ('', '+'):
            return True
    return False


def gpg(*arguments, stdin=None, timeout=PROBE_TIMEOUT):
    try:
        return subprocess.run(['gpg', *arguments], input=stdin, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(['gpg', *arguments], 1, '', '')


def card():
    result = gpg('--card-status', '--with-colons')
    return parse_card(result.stdout) if result.returncode == 0 else None


def key_listing(fingerprint):
    public = gpg('--list-keys', '--with-colons', fingerprint)
    return public.stdout if public.returncode == 0 else ''


def key_state(fingerprint):
    """(primary fingerprint or '', ownertrust, secret listing or '') for a card key."""
    public = key_listing(fingerprint)
    if not public:
        return '', '', ''
    primary, trust = primary_key(public)
    secret = gpg('--list-secret-keys', '--with-colons', fingerprint)
    return primary, trust, secret.stdout if secret.returncode == 0 else ''


def status():
    """Metadata only: never fingerprints, serials, names, addresses or URLs."""
    found = card()
    result = {'card': found is not None, 'imported': False, 'linked': False, 'trusted': False, 'key': None}
    if found and found['fingerprints']:
        primary, trust, secret = key_state(found['fingerprints'][0])
        result.update(imported=bool(primary), linked=bool(secret.strip()), trusted=trust == 'u')
        if primary:
            result['key'] = key_summary(key_listing(found['fingerprints'][0]))
    return result


def confirm(question):
    return input(question + ' [y/N] ').strip().lower() in ('y', 'yes')


def describe(found):
    print('OpenPGP card holder: ' + (found['holder'] or '(not set)'))
    print('Signature key: ' + (found['fingerprints'][0] if found['fingerprints'] else '(no key on the card)'))


def do_import(found):
    url = found['url'] if KEY_URL.fullmatch(found['url']) else ''
    if not found['fingerprints']:
        raise ValueError('The card holds no OpenPGP key to import')
    source = url or 'the configured keyservers'
    if not confirm('Import the public key from ' + source + '?'):
        print('Cancelled; nothing changed.')
        return
    imported = False
    if url:
        imported = subprocess.call(['gpg', '--fetch-keys', url], timeout=NETWORK_TIMEOUT) == 0
        if not imported:
            print('The card URL did not provide the key; trying the keyservers.')
    if not imported:
        imported = subprocess.call(['gpg', '--recv-keys', found['fingerprints'][0]], timeout=NETWORK_TIMEOUT) == 0
    if not imported:
        raise ValueError('The public key could not be fetched; check the card URL or your keyserver')
    # Reading the card again creates the stubs that point gpg at it.
    gpg('--card-status')
    primary, _, secret = key_state(found['fingerprints'][0])
    if not primary or not secret.strip():
        raise ValueError('The key was imported but is not linked to the card; run gpg --card-status')
    print('Key imported and linked to the card. Use trust to mark it as your own key.')


def do_trust(found):
    primary, trust, _ = key_state(found['fingerprints'][0]) if found['fingerprints'] else ('', '', '')
    if not primary:
        raise ValueError('Import the key first')
    if trust == 'u':
        print('The key is already ultimately trusted.')
        return
    print('Ultimate trust makes every signature of this key valid for you. Only do it for your own key.')
    if not confirm('Trust ' + primary + ' ultimately?'):
        print('Cancelled; nothing changed.')
        return
    if gpg('--import-ownertrust', stdin=primary + ':6:\n').returncode != 0:
        raise ValueError('gpg did not accept the ownertrust')
    print('Key trusted ultimately.')


def do_remove(found):
    primary, _, secret = key_state(found['fingerprints'][0]) if found['fingerprints'] else ('', '', '')
    if not primary:
        print('The key is not in your keyring; nothing to remove.')
        return
    if secret.strip() and secret_on_disk(secret):
        raise ValueError('gpg keeps a secret part of this key on disk, not only on the card; remove it manually after a backup')
    print('This removes the public key and the card stubs from your keyring. The key stays on the card and can be imported again.')
    if input('Type REMOVE ' + primary[-8:] + ' to confirm: ').strip() != 'REMOVE ' + primary[-8:]:
        print('Cancelled; nothing changed.')
        return
    option = '--delete-secret-and-public-keys' if secret.strip() else '--delete-keys'
    if gpg('--batch', '--yes', option, primary).returncode != 0:
        raise ValueError('gpg could not remove the key')
    print('Key removed from your keyring.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('operation', choices=['import', 'trust', 'remove'])
    args = parser.parse_args()
    if os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run as the desktop user in an interactive terminal')
    found = card()
    if found is None:
        raise ValueError('No OpenPGP card found: connect the security key')
    describe(found)
    {'import': do_import, 'trust': do_trust, 'remove': do_remove}[args.operation](found)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, EOFError, KeyboardInterrupt) as error:
        print('OpenPGP operation stopped: ' + (str(error) or 'cancelled'), file=sys.stderr)
        raise SystemExit(1)
