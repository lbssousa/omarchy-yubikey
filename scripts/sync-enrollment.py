#!/usr/bin/env python3
"""Signed, reviewed PAM enrollment transfer. Git is an unprivileged transport."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('pam_setup', SOURCE / 'scripts/configure-pam.py')
pam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pam)
NAMESPACE = 'omarchy-yubikey-enrollment-v1'
ORIGIN = 'pam://omarchy'
MAPPING = 'etc/fido2/fido2'
TRUST = 'etc/fido2/sync_allowed_signers'
STATE = 'var/lib/omarchy-yubikey/sync-state.json'
LIMIT = 256 * 1024
FILENAME = 'omarchy-yubikey-enrollment.json'


def username(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\$?', value):
        raise ValueError('Invalid account name')
    return value


def read_regular(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Expected a regular file')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Enrollment input is too large')
    return data


def trusted_path(root, relative, missing=False):
    path = pam.safe_path(root, relative)
    for item in [path, *path.parents]:
        if item == root:
            break
        if not item.exists():
            if missing:
                continue
            raise ValueError('Required root-controlled file is missing')
        info = item.stat()
        if info.st_mode & 0o022 or (root == Path('/') and info.st_uid != 0):
            raise ValueError('Sync trust, state and mapping paths must be root-controlled')
    return path


def validate_credentials(credentials):
    if not isinstance(credentials, list) or len(credentials) > 24:
        raise ValueError('Expected at most 24 credentials')
    handles = set()
    for credential in credentials:
        if not isinstance(credential, str) or len(credential) > 16384:
            raise ValueError('Invalid credential')
        fields = credential.split(',')
        if len(fields) != 4:
            raise ValueError('Sync requires modern four-field pamu2fcfg credentials')
        handle, public_key, algorithm, options = fields
        if algorithm not in ('es256', 'eddsa', 'rs256') or not re.fullmatch(r'(?:\+(?:presence|pin|verification))*', options):
            raise ValueError('Unsupported credential algorithm/options')
        if '+presence' not in options:
            raise ValueError('Synced credentials must require user presence')
        for encoded in (handle, public_key):
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                raise ValueError('Invalid credential encoding') from None
            if not decoded or base64.b64encode(decoded).decode() != encoded:
                raise ValueError('Invalid credential encoding')
        if handle in handles:
            raise ValueError('Duplicate credential handle')
        handles.add(handle)
    return credentials


def decode_bundle(raw, user):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate export field')
            result[key] = value
        return result
    bundle = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(bundle, dict) or set(bundle) != {'schema', 'origin', 'user', 'revision', 'credentials'}:
        raise ValueError('Unexpected export schema')
    if type(bundle['schema']) is not int or bundle['schema'] != 1 or bundle['origin'] != ORIGIN:
        raise ValueError('Unsupported export version or relying party')
    if username(bundle['user']) != username(user):
        raise ValueError('Signed export is for a different account')
    if type(bundle['revision']) is not int or not 1 <= bundle['revision'] <= 2**53 - 1:
        raise ValueError('Revision must be a positive integer')
    validate_credentials(bundle['credentials'])
    return bundle


def credentials_for(mapping, user):
    matches = [line.split(':')[1:] for line in mapping.splitlines() if line.startswith(user + ':')]
    if len(matches) > 1:
        raise ValueError('Duplicate account mapping')
    return matches[0] if matches else []


def replace_user(mapping, user, credentials):
    credentials_for(mapping, user)  # Reject ambiguous existing mappings.
    lines = [line for line in mapping.splitlines() if not line.startswith(user + ':')]
    if credentials:
        lines.append(user + ':' + ':'.join(credentials))
    return '\n'.join(lines) + ('\n' if lines else '')


def verify(raw, signature, allowed, user):
    # Verify the exact in-memory snapshot; never reread untrusted input later.
    with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-verify-') as directory:
        sig = Path(directory) / 'signature'
        trust = Path(directory) / 'allowed_signers'
        sig.write_bytes(signature)
        trust.write_bytes(allowed)
        result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(trust),
                                 '-I', 'omarchy-yubikey:' + user, '-n', NAMESPACE, '-s', str(sig)],
                                input=raw, capture_output=True)
    if result.returncode:
        raise ValueError('Signature verification failed against locally pinned trust')


def import_plan(root, raw, signature, user, minimum_revision=None):
    username(user)
    allowed = read_regular(trusted_path(root, TRUST))
    verify(raw, signature, allowed, user)
    bundle = decode_bundle(raw, user)
    state_path = trusted_path(root, STATE, missing=True)
    state = json.loads(read_regular(state_path)) if state_path.exists() else {}
    if not isinstance(state, dict):
        raise ValueError('Invalid local sync state')
    previous = state.get(user)
    if previous is None and minimum_revision is None:
        raise ValueError('First import requires --minimum-revision from a trusted source')
    floor = minimum_revision if minimum_revision is not None else 1
    if type(floor) is not int or floor < 1:
        raise ValueError('Invalid minimum revision')
    if bundle['revision'] < floor or (previous is not None and bundle['revision'] <= previous['revision']):
        raise ValueError('Old or already imported revision refused')
    mapping_path = trusted_path(root, MAPPING, missing=True)
    mapping = read_regular(mapping_path).decode() if mapping_path.exists() else ''
    old = credentials_for(mapping, user)
    new = bundle['credentials']
    state[user] = {'revision': bundle['revision'], 'sha256': hashlib.sha256(raw).hexdigest()}
    # State first: an interrupted transaction cannot silently replay an old export.
    changes = {
        STATE: ((json.dumps(state, sort_keys=True, indent=2) + '\n').encode(), 0o600),
        MAPPING: (replace_user(mapping, user, new).encode(), 0o644),
    }
    return bundle, old, changes


def export_bundle(args):
    user = username(args.user)
    destination = args.repo.resolve()
    if os.geteuid() == 0:
        raise ValueError('Export and Git operations must run as your normal user')
    # No Git command, hooks, filters, credentials or network ever run as root.
    repository = subprocess.run(['git', '-C', str(destination), 'rev-parse', '--show-toplevel'],
                                check=True, capture_output=True, text=True).stdout.strip()
    if Path(repository).resolve() != destination or destination == SOURCE or SOURCE in destination.parents:
        raise ValueError('Use a separate, existing private Git checkout')
    path = destination / FILENAME
    for target in (path, Path(str(path) + '.sig')):
        if target.exists() or target.is_symlink():
            raise ValueError('Export exists; review and remove the previous export pair before replacing it')
    mapping = read_regular(args.mapping).decode()
    bundle = {'schema': 1, 'origin': ORIGIN, 'user': user, 'revision': args.revision,
              'credentials': credentials_for(mapping, user)}
    raw = (json.dumps(bundle, sort_keys=True, indent=2) + '\n').encode()
    decode_bundle(raw, user)
    # Sign in a private temporary directory; a failure leaves no unsigned export.
    with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-export-') as directory:
        temporary = Path(directory) / FILENAME
        temporary.write_bytes(raw)
        subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(args.signing_key.resolve()),
                        '-n', NAMESPACE, str(temporary)], check=True)
        signature = read_regular(Path(str(temporary) + '.sig'))
        for target, data in ((path, raw), (Path(str(path) + '.sig'), signature)):
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    print('Signed export created. Review, commit and push the two export files as your normal user.')
    print('Repository privacy is your responsibility; exports are signed, not encrypted.')


def import_bundle(args):
    if os.geteuid() != 0:
        raise ValueError('Import needs sudo; Git fetch/pull must run separately as your normal user')
    root = Path('/')
    raw = read_regular(args.bundle)
    signature = read_regular(Path(str(args.bundle) + '.sig'))
    with pam.configuration_lock(root):
        bundle, old, changes = import_plan(root, raw, signature, args.user, args.minimum_revision)
        print(f"Verified account: {bundle['user']}; revision: {bundle['revision']}")
        print(f"Credentials: {len(old)} -> {len(bundle['credentials'])}")
        for label, items in (('Remove', set(old) - set(bundle['credentials'])),
                             ('Add', set(bundle['credentials']) - set(old))):
            for value in sorted(items):
                print(f'  {label}: SHA256:{hashlib.sha256(value.encode()).hexdigest()}')
        if not args.apply:
            print('Preview only. Repeat with --apply for an interactive, backed-up import.')
            return
        confirmation = f"IMPORT {bundle['user']} revision {bundle['revision']}"
        with open('/dev/tty', 'r+') as terminal:
            terminal.write(f'This replaces all key mappings for this account. Type {confirmation}: ')
            terminal.flush()
            if terminal.readline().strip() != confirmation:
                raise ValueError('Import cancelled')
        backup = pam.apply(root, changes)
        print(f'Imported. Root-only backup: {backup}')
        print('Test authentication before closing your recovery shell. See docs/enrollment-sync.md.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export', help='Sign a snapshot into a separate Git checkout')
    export.add_argument('--repo', type=Path, required=True)
    export.add_argument('--mapping', type=Path, default=Path('/etc/fido2/fido2'))
    export.add_argument('--user', required=True)
    export.add_argument('--revision', type=int, required=True)
    export.add_argument('--signing-key', type=Path, required=True)
    incoming = commands.add_parser('import', help='Verify and review a downloaded signed snapshot')
    incoming.add_argument('bundle', type=Path)
    incoming.add_argument('--user', required=True)
    incoming.add_argument('--minimum-revision', type=int)
    incoming.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    export_bundle(args) if args.command == 'export' else import_bundle(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError, TypeError) as error:
        # Parsing/command output can contain credential data: print no payload.
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, (json.JSONDecodeError, UnicodeError)) else type(error).__name__
        print(f'Sync stopped: {message}', file=sys.stderr)
        sys.exit(1)
