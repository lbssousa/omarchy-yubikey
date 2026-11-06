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
trusted, plus bounded public identity and per-slot state. Card serials, URLs
and secret material never enter the window.
"""
import argparse
import datetime
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unicodedata
from urllib.parse import unquote

PROBE_TIMEOUT = 5
NETWORK_TIMEOUT = 60
KEY_URL = re.compile(r'(?:https?|hkps?)://[\x21-\x7e]{1,2048}')
CURVES = {'ed25519', 'cv25519', 'ed448', 'cv448', 'nistp256', 'nistp384', 'nistp521',
          'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1'}
RSA = {'1', '2', '3'}
FINGERPRINT = re.compile(r'(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})')
ROLES = ('sign', 'encrypt', 'authenticate')


def public_text(value, limit=256):
    """Bound public labels and remove controls, including bidi overrides."""
    return ''.join(c for c in value if c.isprintable() and not unicodedata.category(c).startswith('C'))[:limit]


def unescape_colons(value):
    # gpg --with-colons escapes ':' and control characters as "\xHH".
    data = re.sub(rb'\\x([0-9A-Fa-f]{2})', lambda match: bytes([int(match[1], 16)]), value.encode('utf-8'))
    return data.decode('utf-8', errors='replace')


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
    fingerprints = fields.get('fpr', [])
    slots = {role: fingerprints[i].upper() if i < len(fingerprints) and FINGERPRINT.fullmatch(fingerprints[i]) else ''
             for i, role in enumerate(ROLES)}
    serial = next((value.upper() for value in reader if re.fullmatch(r'[0-9A-Fa-f]{16,64}', value)), '')
    return {'holder': public_text(holder), 'url': get('url', 0), 'serial': serial,
            'slots': slots, 'fingerprints': [value for value in slots.values() if value]}


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
    if pub[6].isdecimal() and int(pub[6]):
        moment = datetime.datetime.fromtimestamp(int(pub[6]), datetime.timezone.utc)
        expires = moment.strftime('%Y-%m-%d')
        expired = expired or moment < (now or datetime.datetime.now(datetime.timezone.utc))
    capabilities = pub[11]
    uids = sum(1 for line in text.splitlines() if line.startswith('uid:') and line.split(':')[1] != 'r')
    primary, _ = primary_key(text)
    uid = next((unescape_colons(line.split(':')[9]) for line in text.splitlines()
                if line.startswith('uid:') and len(line.split(':')) > 9 and line.split(':')[1] not in ('r', 'e', 'i')), '')
    return {'algorithm': algorithm, 'sign': 'S' in capabilities, 'encrypt': 'E' in capabilities,
            'authenticate': 'A' in capabilities, 'expires': expires, 'expired': expired, 'uids': uids,
            'revoked': pub[1] == 'r', 'disabled': 'D' in capabilities,
            'fingerprint': primary.upper() if FINGERPRINT.fullmatch(primary) else '', 'uid': public_text(uid)}


def key_records(text):
    """Associate each full fingerprint with its own public/secret key record."""
    records, current = {}, None
    for line in text.splitlines():
        fields = line.split(':')
        if fields[0] in ('pub', 'sub', 'sec', 'ssb'):
            current = fields + [''] * max(0, 17 - len(fields))
        elif fields[0] == 'fpr' and current is not None and len(fields) > 9 and FINGERPRINT.fullmatch(fields[9]):
            records[fields[9].upper()] = current
            current = None
    return records


def slot_states(found, public, secret):
    pubs, secrets = key_records(public), key_records(secret)
    primary = key_summary(public)
    primary_usable = bool(primary) and not any(primary[x] for x in ('expired', 'revoked', 'disabled'))
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    result = {}
    for role, fingerprint in found['slots'].items():
        pub, sec = pubs.get(fingerprint), secrets.get(fingerprint)
        token = sec[14].upper() if sec else ''
        location = ('disk' if token in ('', '+') else 'card' if token == found['serial'] and token else
                    'other-card' if token != '#' else 'missing') if sec else 'missing'
        linked = bool(fingerprint) and location == 'card'
        usable = bool(pub) and pub[1] not in ('r', 'e', 'i', 'd') and 'D' not in pub[11]
        if pub and pub[6].isdecimal() and int(pub[6]) and int(pub[6]) <= now:
            usable = False
        usable = usable and role[0] in pub[11].lower() if pub else False
        # authenticate uses 'a', encrypt 'e', sign 's'.
        result[role] = {'present': bool(fingerprint), 'linked': linked, 'location': location,
                        'ready': linked and usable and primary_usable}
    return result


def secret_on_disk(colons):
    """Whether a --list-secret-keys --with-colons listing has a secret part kept
    in the keyring rather than on a card. Field 15 holds the card serial for a
    stub, "#" for a simple stub, and "+" or nothing for a local secret."""
    for line in colons.splitlines():
        fields = line.split(':')
        if fields[0] in ('sec', 'ssb') and (fields[14] if len(fields) > 14 else '') in ('', '+'):
            return True
    return False


def gpg(*arguments, stdin=None, timeout=PROBE_TIMEOUT, homedir=None):
    command = ['gpg', *(['--homedir', str(homedir), '--no-options'] if homedir else []), *arguments]
    try:
        return subprocess.run(command, input=stdin, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(['gpg', *arguments], 1, '', '')


def card():
    result = gpg('--card-status', '--with-colons')
    return parse_card(result.stdout) if result.returncode == 0 else None


def key_listing(fingerprint, homedir=None):
    public = gpg('--list-keys', '--with-colons', fingerprint, homedir=homedir)
    return public.stdout if public.returncode == 0 else ''


def key_state(fingerprint):
    """(primary fingerprint or '', ownertrust, secret listing or '') for a card key."""
    public = key_listing(fingerprint)
    if not public:
        return '', '', ''
    primary, trust = primary_key(public)
    # A filtered GnuPG query returns an error both for "no secret exists" and
    # for actual inspection failures. An unfiltered listing distinguishes an
    # empty successful keyring from an agent/query error; select the exact
    # primary certificate locally so unrelated local keys do not affect it.
    secret = gpg('--list-secret-keys', '--with-colons')
    if secret.returncode != 0:
        raise ValueError('Could not inspect secret keys; no changes made')
    blocks = re.split(r'(?=^sec:)', secret.stdout, flags=re.MULTILINE)
    matching = [block for block in blocks if primary_key(block)[0] == primary]
    if len(matching) > 1:
        raise ValueError('Ambiguous secret-key listing; no changes made')
    return primary, trust, matching[0] if len(matching) == 1 else ''


def status():
    """Bounded public identity and state, never card serials, URLs or secrets."""
    found = card()
    result = {'card': found is not None, 'imported': False, 'linked': False, 'trusted': False,
              'ready': False, 'local': False, 'key': None, 'slots': {}}
    if found and found['fingerprints']:
        primary, trust, secret = key_state(found['fingerprints'][0])
        result.update(imported=bool(primary), trusted=trust == 'u', local=secret_on_disk(secret))
        if primary:
            public = key_listing(found['fingerprints'][0])
            result['key'] = key_summary(public)
            result['slots'] = slot_states(found, public, secret)
            present = [slot for slot in result['slots'].values() if slot['present']]
            result['linked'] = bool(present) and all(slot['linked'] for slot in present)
            result['ready'] = bool(present) and all(slot['ready'] for slot in present)
    return result


def confirm(question):
    return input(question + ' [y/N] ').strip().lower() in ('y', 'yes')


def describe(found):
    print('OpenPGP card holder: ' + (found['holder'] or '(not set)'))
    print('Card key: ' + (found['fingerprints'][0] if found['fingerprints'] else '(no key on the card)'))


def configured_keyservers():
    """Carry only configured dirmngr keyserver URLs into the isolated home.

    Importing the account's whole gpg.conf would permit alternate keyring paths
    and defeat staging. gpgconf supplies the parsed, percent-escaped setting.
    """
    result = subprocess.run(['gpgconf', '--list-options', 'dirmngr'], capture_output=True,
                            text=True, timeout=PROBE_TIMEOUT, check=False)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            fields = line.split(':')
            if len(fields) > 9 and fields[0] == 'keyserver':
                return [url for value in fields[9].split(',')
                        if KEY_URL.fullmatch(url := unquote(value.removeprefix('"')))]
    return []


def do_import(found):
    url = found['url'] if KEY_URL.fullmatch(found['url']) else ''
    if not found['fingerprints']:
        raise ValueError('The card holds no OpenPGP key to import')
    source = url or 'the configured keyservers'
    if not confirm('Import the public key from ' + source + '?'):
        print('Cancelled; nothing changed.')
        return
    with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-openpgp-') as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        keyservers = configured_keyservers()
        if keyservers:
            (directory / 'dirmngr.conf').write_text(''.join('keyserver ' + value + '\n' for value in keyservers))
            os.chmod(directory / 'dirmngr.conf', 0o600)
        try:
            imported = False
            sources = [('--fetch-keys', url)] if url else []
            sources.append(('--recv-keys', found['fingerprints'][0]))
            for operation, source in sources:
                fetched = gpg('--batch', operation, source, timeout=NETWORK_TIMEOUT, homedir=directory)
                public = key_listing(found['fingerprints'][0], homedir=directory) if fetched.returncode == 0 else ''
                # A URL may return several keys, or the wrong key with exit status 0.
                # Select only the certificate containing every populated card slot.
                if not public or not set(found['fingerprints']) <= key_records(public).keys():
                    print('Source did not provide the matching card key; trying the next source.')
                    continue
                primary, _ = primary_key(public)
                exported = gpg('--armor', '--export', primary, homedir=directory)
                if exported.returncode or not exported.stdout.strip():
                    continue
                if gpg('--import', stdin=exported.stdout, timeout=NETWORK_TIMEOUT).returncode:
                    raise ValueError('The verified public key could not be imported')
                imported = True
                break
            if not imported:
                raise ValueError('No matching public key was fetched; your keyring was not changed')
        finally:
            # Do not leave agents or dirmngr processes referring to the deleted home.
            subprocess.run(['gpgconf', '--homedir', str(directory), '--kill', 'all'],
                           capture_output=True, timeout=PROBE_TIMEOUT, check=False)
    # Reading the card again creates the stubs that point gpg at it.
    gpg('--card-status')
    current = card()
    if not current or current['serial'] != found['serial'] or current['slots'] != found['slots']:
        raise ValueError('The card changed during import; the verified public key was imported, but linking was not confirmed')
    primary, _, secret = key_state(found['fingerprints'][0])
    slots = slot_states(found, key_listing(found['fingerprints'][0]), secret)
    if not primary or not all(slot['linked'] for slot in slots.values() if slot['present']):
        raise ValueError('Public key imported; some card keys are not linked. Local secret copies are never replaced. Review gpg --card-status.')
    print('Key imported and linked to the card. Ownertrust is a separate, optional choice.')


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
    # The keyring can change while the confirmation prompt is open.
    checked_primary, _, secret = key_state(found['fingerprints'][0])
    if checked_primary != primary or secret_on_disk(secret):
        raise ValueError('The keyring changed or contains a local secret; nothing was removed')
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
