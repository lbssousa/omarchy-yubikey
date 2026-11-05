#!/usr/bin/env python3
"""Copy the resident SSH keys of a security key into ~/.ssh, or remove copies.

Interactive terminal operations, run as the desktop user without privileges:

  import  `ssh-keygen -K` in a private temporary directory, where ssh-keygen
          itself asks for the FIDO2 PIN, a touch and an optional passphrase;
          then each key file pair is moved into ~/.ssh, never over a file
          already there
  remove  delete one copied key file pair from ~/.ssh; the credential stays on
          the security key and can be imported again

`status()` is the metadata-only probe used by the control center: how many
resident key files ~/.ssh holds, without names.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

RESIDENT = re.compile(r'id_[a-z0-9]+_sk_rk[A-Za-z0-9_.:@-]*')
IMPORT_TIMEOUT = 180


def ssh_directory():
    return Path.home() / '.ssh'


def resident_keys(directory):
    """Private key files ssh-keygen -K wrote, without their .pub halves."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    return sorted(name for name in names if RESIDENT.fullmatch(name) and not name.endswith('.pub')
                  and not (directory / name).is_symlink() and (directory / name).is_file())


def status():
    return {'count': len(resident_keys(ssh_directory()))}


def copy_exclusive(source, target, mode):
    """Create <target> only if nothing is there, even if it appears meanwhile."""
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream, open(source, 'rb') as data:
        shutil.copyfileobj(data, stream)
    os.chmod(target, mode)


def install(workdir, directory):
    """Move downloaded pairs into <directory>; return (imported, skipped) names."""
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('~/.ssh must be a directory')
    imported, skipped = [], []
    for name in resident_keys(workdir):
        pair = [(name, 0o600), (name + '.pub', 0o644)]
        if any(os.path.lexists(directory / item) for item, _ in pair):
            skipped.append(name)
            continue
        written = []
        try:
            for item, mode in pair:
                if (workdir / item).is_file():
                    copy_exclusive(workdir / item, directory / item, mode)
                    written.append(directory / item)
        except FileExistsError:
            for path in written:
                path.unlink(missing_ok=True)
            skipped.append(name)
            continue
        imported.append(name)
    return imported, skipped


def do_import():
    runtime = os.environ.get('XDG_RUNTIME_DIR')
    base = runtime if runtime and os.path.isdir(runtime) else None
    print('ssh-keygen asks for the FIDO2 PIN and a touch, then for a passphrase to protect each copied file.')
    with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-ssh-', dir=base) as temporary:
        workdir = Path(temporary)
        os.chmod(workdir, 0o700)
        result = subprocess.call(['ssh-keygen', '-K'], cwd=workdir, timeout=IMPORT_TIMEOUT)
        if not resident_keys(workdir):
            if result:
                raise ValueError('ssh-keygen could not read resident keys from the security key')
            print('The security key holds no resident SSH keys; nothing changed.')
            return
        imported, skipped = install(workdir, ssh_directory())
    for name in imported:
        print('Imported ~/.ssh/' + name)
    for name in skipped:
        print('Kept the existing ~/.ssh/' + name + '; that key was not copied again.')


def do_remove():
    directory = ssh_directory()
    names = resident_keys(directory)
    if not names:
        print('No resident key files in ~/.ssh; nothing to remove.')
        return
    print('The credential stays on the security key; only the copy in ~/.ssh is removed.')
    for index, name in enumerate(names, 1):
        print(str(index) + '. ' + name)
    selected = input('Number to remove, or Enter to cancel: ').strip()
    if not selected:
        return
    if not selected.isdecimal() or not 1 <= int(selected) <= len(names):
        raise ValueError('Invalid selection')
    name = names[int(selected) - 1]
    if input('Remove ~/.ssh/' + name + ' and its .pub? [y/N] ').strip().lower() not in ('y', 'yes'):
        print('Cancelled; nothing changed.')
        return
    for item in (name, name + '.pub'):
        path = directory / item
        if os.path.lexists(path):
            path.unlink()
    print('Removed ~/.ssh/' + name + '.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('operation', choices=['import', 'remove'])
    args = parser.parse_args()
    if os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run as the desktop user in an interactive terminal')
    (do_import if args.operation == 'import' else do_remove)()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, EOFError, KeyboardInterrupt) as error:
        print('SSH key operation stopped: ' + (str(error) or 'cancelled'), file=sys.stderr)
        raise SystemExit(1)
