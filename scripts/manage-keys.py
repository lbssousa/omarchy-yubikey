#!/usr/bin/env python3
"""Interactive per-account PAM key management; never changes shared PAM policy."""
import argparse
import getpass
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('managed_pam', SOURCE / 'configure-pam.py')
pam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pam)


def configure(*arguments):
    return ['sudo', sys.executable, str(SOURCE / 'configure-pam.py'), *arguments]


HELPER = Path('/usr/local/libexec/omarchy-yubikey/key-mapping-helper')
MAPPING = Path('/etc/fido2/fido2')


def helper_installed():
    """The root-owned per-account helper from install.sh, if any (see docs/multi-user.md)."""
    try:
        info = HELPER.lstat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and shutil.which('pkexec') is not None)


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
        with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-enroll-') as directory:
            path = Path(directory) / 'enrollment'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                subprocess.run(['pamu2fcfg', '-N', '-u', username, '-o', 'pam://omarchy', '-i', 'pam://omarchy'], stdout=stream, check=True)
            references = pam.key_references(path.read_text(), username)
            if len(references) != 1:
                raise ValueError('Enrollment did not produce exactly one key; nothing installed')
            print('Key reference (save it to identify this enrollment later): ' + references[0])
            if helper_installed():
                # Preview without privileges: the mapping is public, and the helper
                # recomputes the same plan under the transaction lock.
                pam.plan(Path('/'), [], path.read_text(), username)
                print('Planned change: /etc/fido2/fido2 (your account only; values hidden)')
                if input('Apply this enrollment? [y/N] ').strip().lower() not in ('y', 'yes'):
                    return
                print('Authenticate as yourself to save the key.')
                with path.open() as stream:
                    subprocess.run(['pkexec', str(HELPER), 'add'], stdin=stream, check=True)
            else:
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
        if helper_installed():
            pam.remove_key_plan(Path('/'), username, reference)
            print('Planned change: /etc/fido2/fido2 (your account only; values hidden)')
            command = ['pkexec', str(HELPER), 'remove', reference]
        else:
            command = configure('--user', username, '--remove-key', reference)
            subprocess.run(command, check=True)
            command = command + ['--apply']
        if input('Type REMOVE ' + reference[-8:] + ' to confirm: ').strip() != 'REMOVE ' + reference[-8:]:
            print('Cancelled; nothing changed.')
            return
        subprocess.run(command, check=True)
        print('Registration removed. This does not erase credentials on the physical key or remove Keyring/LUKS enrollments.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, EOFError, KeyboardInterrupt):
        print('Key management stopped. Completed changes retain their printed rollback ID.', file=sys.stderr)
        raise SystemExit(1)
