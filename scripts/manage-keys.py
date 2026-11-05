#!/usr/bin/env python3
"""Interactive per-account PAM key management; never changes shared PAM policy."""
import argparse
import base64
import getpass
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('managed_pam', SOURCE / 'configure-pam.py')
pam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pam)

MAPPING = Path('/etc/fido2/fido2')
ORIGIN = 'pam://omarchy'
PROBE_TIMEOUT = 5


def configure(*arguments):
    return ['sudo', sys.executable, str(SOURCE / 'configure-pam.py'), *arguments]


def credentials(mapping, username):
    """The account's credentials, validated like the references printed for them."""
    pam.key_references(mapping, username)
    rows = [line for line in mapping.splitlines() if line.startswith(username + ':')]
    return rows[0].split(':')[1:] if rows else []


def connected_devices():
    result = subprocess.run(['fido2-token', '-L'], capture_output=True, text=True, timeout=PROBE_TIMEOUT, check=False)
    if result.returncode != 0:
        raise ValueError('Could not list security keys')
    return [line.split(': ', 1)[0] for line in result.stdout.splitlines() if line.strip()]


def already_enrolled(device, enrolled):
    """Whether the connected key created one of the account's credentials.

    A non-resident credential only produces an assertion on the key that created
    it, and up=false asks for no touch, so this neither blinks nor consumes a PIN
    retry. Any failure (another key, another origin, a key refusing silent
    assertions) counts as no match; enrollment then proceeds as before.
    """
    for credential in enrolled:
        handle = credential.split(',', 1)[0]
        challenge = base64.b64encode(os.urandom(32)).decode()
        try:
            result = subprocess.run(['fido2-assert', '-G', '-t', 'up=false', device],
                                    input='\n'.join((challenge, ORIGIN, handle)) + '\n',
                                    capture_output=True, text=True, timeout=PROBE_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return True
    return False


def check_new_key(username):
    """Refuse a second enrollment of a key the account already uses."""
    enrolled = credentials(MAPPING.read_text() if MAPPING.exists() else '', username)
    devices = connected_devices()
    if len(devices) != 1:
        raise ValueError('Connect exactly one security key: the new or backup key')
    if enrolled and already_enrolled(devices[0], enrolled):
        print('This security key is already enrolled for your account; nothing changed.')
        print('Connect the backup key you want to add instead.')
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['add', 'remove'])
    args = parser.parse_args()
    if os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run as the desktop user in an interactive terminal')
    username = getpass.getuser()
    if args.operation == 'add':
        print('This adds a key for your account without changing sudo, desktop or other users’ policies.')
        print('The new credential requires a configured FIDO2 PIN and touch.')
        input('Connect only the new/backup key, then press Enter. ')
        check_new_key(username)
        with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-enroll-') as directory:
            path = Path(directory) / 'enrollment'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                subprocess.run(['pamu2fcfg', '-N', '-u', username, '-o', 'pam://omarchy', '-i', 'pam://omarchy'], stdout=stream, check=True)
            references = pam.key_references(path.read_text(), username)
            if len(references) != 1:
                raise ValueError('Enrollment did not produce exactly one key; nothing installed')
            print('Key reference (save it to identify this enrollment later): ' + references[0])
            command = configure('--user', username, '--enrollment-only', '--enrollment', str(path))
            subprocess.run(command, check=True)
            if input('Apply this enrollment? [y/N] ').strip().lower() not in ('y', 'yes'):
                return
            subprocess.run(command + ['--apply'], check=True)
        print('Key enrolled. Test it with sudo and every desktop method you use.')
    else:
        mapping = MAPPING.read_text()
        references = pam.key_references(mapping, username)
        if len(references) <= 1:
            raise ValueError('Keep at least one enrolled key; the last key cannot be removed here')
        print('These references identify registrations, not physical serial numbers.')
        print('Match the reference saved during enrollment. Do not guess which physical key an older registration belongs to.')
        for i, reference in enumerate(references, 1):
            print(str(i) + '. ' + reference)
        selected = input('Number to remove, or Enter to cancel: ').strip()
        if not selected:
            return
        if not selected.isdecimal() or not 1 <= int(selected) <= len(references):
            raise ValueError('Invalid selection')
        reference = references[int(selected) - 1]
        command = configure('--user', username, '--remove-key', reference)
        subprocess.run(command, check=True)
        if input('Type REMOVE ' + reference[-8:] + ' to confirm: ').strip() != 'REMOVE ' + reference[-8:]:
            print('Cancelled; nothing changed.')
            return
        subprocess.run(command + ['--apply'], check=True)
        print('Registration removed. This does not erase credentials on the physical key or remove Keyring/LUKS enrollments.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, EOFError, KeyboardInterrupt):
        print('Key management stopped. Completed changes retain their printed rollback ID.', file=sys.stderr)
        raise SystemExit(1)
