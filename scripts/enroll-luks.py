#!/usr/bin/env python3
"""Opt-in LUKS2 enrollment. Boot configuration is a separate, reviewed step."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n import tr

BACKUPS = Path('/var/lib/omarchy-yubikey/luks-backups')


def run(*command, capture=False):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None, check=False)
    if result.returncode:
        # Never echo captured header metadata, identifiers, or credential values.
        raise RuntimeError(tr('%1 failed; stopped without changing boot configuration', Path(command[0]).name))
    return result.stdout if capture else None


def metadata(device):
    return json.loads(run('cryptsetup', 'luksDump', '--dump-json-metadata', device, capture=True))


def fido_tokens(header):
    return {key for key, value in header.get('tokens', {}).items()
            if value.get('type') == 'systemd-fido2'}


def preserved(before, after):
    return (before.get('segments') == after.get('segments')
            and all(after.get('keyslots', {}).get(k) == v for k, v in before.get('keyslots', {}).items())
            and all(after.get('tokens', {}).get(k) == v for k, v in before.get('tokens', {}).items()))


def preflight(device):
    if not Path(device).is_block_device():
        raise ValueError(tr('--device must identify an existing block device'))
    for program in ('cryptsetup', 'systemd-cryptenroll', 'fido2-token'):
        if not shutil.which(program):
            raise ValueError(tr('Missing %1; on Arch install cryptsetup, systemd and libfido2', program))
    if not Path('/usr/lib/cryptsetup/libcryptsetup-token-systemd-fido2.so').is_file():
        raise ValueError(tr('The systemd FIDO2 cryptsetup token plugin is missing'))
    run('cryptsetup', 'isLuks', '--type', 'luks2', device, capture=True)
    header = metadata(device)
    if not header.get('keyslots'):
        raise ValueError(tr('No existing LUKS keyslots; a working passphrase is required'))
    return header


def confirm(prompt, default=False):
    reply = input(tr(prompt) + (' [Y/n] ' if default else ' [y/N] ')).strip().lower()
    return default if not reply else reply in ('y', 'yes')


def private_backup(base=BACKUPS):
    # The destination is fixed outside the source checkout. Refuse symlinked
    # ancestors, and never relax an existing directory's permissions.
    for path in reversed([base, *base.parents]):
        if path.is_symlink():
            raise ValueError(tr('Refusing a symbolic-link backup directory'))
        if not path.exists():
            path.mkdir(mode=0o700)
    for path in (base.parent, base):
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError(tr('The project backup directories must be owner-only (0700)'))
    prefix = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-')
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def backup_header(device, destination):
    run('cryptsetup', 'luksHeaderBackup', device, '--header-backup-file', str(destination))
    destination.chmod(0o600)


def wait_for_key():
    while True:
        input(tr('Connect only the key to enroll, then press Enter. '))
        listing = run('fido2-token', '-L', capture=True)
        if len([line for line in listing.splitlines() if line.strip()]) == 1:
            return
        print(tr('Exactly one FIDO2 key must be connected. Device details are hidden.'))


def enroll_key(device):
    wait_for_key()
    before = metadata(device)
    print(tr('Enter the disk passphrase, then the security-key PIN, and touch the key.'))
    run('systemd-cryptenroll', device, '--fido2-device=auto',
        '--fido2-with-client-pin=yes', '--fido2-with-user-presence=yes')
    after = metadata(device)
    added = fido_tokens(after) - fido_tokens(before)
    if not preserved(before, after) or len(added) != 1:
        raise RuntimeError(tr('Unexpected enrollment result; review locally before proceeding'))
    token = added.pop()
    if not re.fullmatch(r'[0-9]+', token):
        raise ValueError(tr('Unexpected token index'))
    print(tr('Test this new key: enter its PIN and touch it again. No device will be mapped.'))
    run('cryptsetup', 'open', '--test-passphrase', '--token-only', '--token-id', token, device)
    print(tr('New key verified. Existing slots were preserved.'))


def enroll(device):
    print(tr('LUKS2 enrollment only. This does not change initramfs, boot files, PAM or plugins.'))
    print(tr('Keep a working disk passphrase and recovery media. Do not record this terminal.'))
    print(tr('The recovery key, if requested, is shown by systemd directly in this terminal.'))
    if input(tr('Type ENROLL to add keys to the selected device: ')).strip() != 'ENROLL':
        print(tr('Cancelled; nothing changed.'))
        return
    print(tr('First verify your existing disk passphrase (external tokens are disabled).'))
    run('cryptsetup', 'open', '--test-passphrase', '--disable-external-tokens', device)
    backup = private_backup()
    print(tr('Private local backup directory: %1', backup))
    backup_header(device, backup / 'header-before.img')
    print(tr('Header backed up. Copy it to private offline storage before relying on this setup.'))
    enroll_key(device)
    while confirm('Enroll another backup key?'):
        enroll_key(device)
    if confirm('Create an additional recovery key to keep offline?', default=True):
        before = metadata(device)
        run('systemd-cryptenroll', device, '--recovery-key')
        if not preserved(before, metadata(device)):
            raise RuntimeError(tr('Unexpected recovery enrollment result; review locally'))
        input(tr('Write the recovery key on paper or store it securely offline, then press Enter. '))
    backup_header(device, backup / 'header-after.img')
    print(tr('Enrollment complete. No keyslots were removed; your disk passphrase remains usable.'))
    print(tr('Boot integration is a separate manual step: docs/luks.md. Do not reboot into an unverified image.'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', help='Override the Omarchy display language')
    parser.add_argument('--device', required=True, help='Explicit existing LUKS2 partition; never guessed')
    parser.add_argument('--check', action='store_true', help='Read-only prerequisite/header check; no enrollment or backup')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error(tr('Run through ./install.sh --luks, which uses sudo'))
    device = str(Path(args.device).resolve())
    preflight(device)
    if args.check:
        print(tr('LUKS2 prerequisites passed. No changes made. This does not qualify boot compatibility.'))
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error(tr('An interactive terminal is required; do not pipe or log enrollment'))
    os.umask(0o077)
    enroll(device)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, EOFError, KeyboardInterrupt) as error:
        if isinstance(error, (ValueError, RuntimeError)):
            print(tr('Reason: %1', error), file=sys.stderr)
        print(tr('LUKS setup stopped. Boot configuration was not changed. Any already-added keys remain enrolled; no slots are automatically removed. Keep the private backups and review docs/luks.md.'), file=sys.stderr)
        sys.exit(1)
