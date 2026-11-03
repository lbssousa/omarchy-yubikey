#!/usr/bin/env python3
"""Conservative Arch PAM configuration with versioned backups and rollback."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

AUTH = 'auth sufficient pam_u2f.so cue origin=pam://omarchy appid=pam://omarchy authfile=/etc/fido2/fido2'
LOCK = '#%PAM-1.0\nauth required pam_u2f.so origin=pam://omarchy appid=pam://omarchy authfile=/etc/fido2/fido2\naccount include system-local-login\n'
GATE = 'usr/local/lib/security/pam_omarchy_fallback.so'
GATE_AUTH = 'auth requisite /' + GATE
TARGETS = {'etc/pam.d/sudo', 'etc/pam.d/polkit-1', 'etc/pam.d/omarchy-lock-fido2', 'etc/fido2/fido2', GATE, 'var/lib/omarchy-yubikey/sync-state.json'}
BACKUPS = Path('var/lib/omarchy-yubikey/backups')


def key_auth(mode='pin'):
    if mode not in ('pin', 'touch'):
        raise ValueError('Unsupported authentication mode')
    return AUTH + (' pinverification=1 userpresence=1' if mode == 'pin' else ' userpresence=1')


def lock_config(mode='pin'):
    return LOCK.replace('authfile=/etc/fido2/fido2', 'authfile=/etc/fido2/fido2' +
                        (' pinverification=1 userpresence=1' if mode == 'pin' else ' userpresence=1'))


def safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe configuration path')
    path = root / relative
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError(f'Refusing symbolic link: {parent}')
    return path


@contextmanager
def configuration_lock(root):
    directory = safe_path(root, 'var/lib/omarchy-yubikey')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for item in [directory, *directory.parents]:
        if item == root:
            break
        info = item.stat()
        if info.st_mode & 0o022 or (root == Path('/') and info.st_uid != 0):
            raise ValueError('Configuration directories must be root-controlled')
    path = safe_path(root, 'var/lib/omarchy-yubikey/config.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or (root == Path('/') and info.st_uid != 0):
            raise ValueError('Configuration lock must be a root-controlled regular file')
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def active_lines(text):
    return [' '.join(line.split()) for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]


def pam_with_key(text, mode='pin', fallback='explicit'):
    lines = active_lines(text)
    auth = [line for line in lines if line.startswith(('auth ', '-auth '))]
    known = [[AUTH, 'auth include system-auth'], ['auth include system-auth']]
    for old_mode in ('pin', 'touch'):
        for old_fallback in ('explicit', 'automatic'):
            known.append([key_auth(old_mode)] + ([GATE_AUTH] if old_fallback == 'explicit' else []) + ['auth include system-auth'])
    if auth not in known or 'account include system-auth' not in lines:
        raise ValueError('Custom PAM authentication stack: left untouched. Use docs/pam-setup.md for manual review.')
    if fallback not in ('explicit', 'automatic'):
        raise ValueError('Unsupported fallback policy')
    desired = [key_auth(mode)] + ([GATE_AUTH] if fallback == 'explicit' else [])
    original = [line for line in text.splitlines(keepends=True)
                if not re.match(r'^\s*auth\s+', line) or ' '.join(line.split()) == 'auth include system-auth']
    index = next(i for i, line in enumerate(original) if re.match(r'^\s*auth\s+', line))
    original[index:index] = [line + '\n' for line in desired]
    return ''.join(original)


def merge_mapping(existing, enrollment, username):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\$?', username):
        raise ValueError('Unsupported account name')
    entry = enrollment.strip()
    if '\n' in entry or '\r' in entry or not entry.startswith(username + ':'):
        raise ValueError('Enrollment must contain one line for the selected user')
    added = entry.split(':')[1:]
    if not added or any(not item or ',' not in item or re.search(r'\s', item) for item in added):
        raise ValueError('Enrollment is empty or malformed')
    lines = existing.splitlines()
    matches = [i for i, line in enumerate(lines) if line.startswith(username + ':')]
    if len(matches) > 1:
        raise ValueError('Duplicate user entries in existing mapping: merge manually first')
    if matches:
        index = matches[0]
        credentials = lines[index].split(':')[1:]
        for credential in added:
            if credential not in credentials:
                credentials.append(credential)
        lines[index] = username + ':' + ':'.join(credentials)
    else:
        lines.append(entry)
    return '\n'.join(lines) + '\n'


def plan(root, services, enrollment, username, mode='pin', fallback='explicit', gate=None):
    changes = {}
    key_auth(mode)  # Validate even when only the lock is selected.
    if fallback not in ('explicit', 'automatic'):
        raise ValueError('Unsupported fallback policy')
    if fallback == 'explicit' and any(s in ('sudo', 'polkit-1') for s in services):
        target = safe_path(root, GATE)
        if gate is not None:
            if not gate.startswith(b'\x7fELF'):
                raise ValueError('Build the fallback PAM module first')
            if not target.exists() or target.read_bytes() != gate:
                changes[GATE] = (gate, 0o644)
        elif not target.is_file():
            raise ValueError('Explicit fallback needs --fallback-module built by scripts/build-pam-gate.sh')
        if target.exists() and (target.stat().st_mode & 0o022 or (root == Path('/') and target.stat().st_uid != 0)):
            raise ValueError('Fallback module must be root-controlled')
    for service in services:
        relative = f'etc/pam.d/{service}'
        target = safe_path(root, relative)
        if service == 'omarchy-lock-fido2':
            if not safe_path(root, 'etc/pam.d/omarchy-lock-password').is_file():
                raise ValueError('The shell password-lock PAM service is missing; desktop setup was not changed')
            known_locks = [active_lines(item) for item in (LOCK, lock_config('pin'), lock_config('touch'))]
            if target.exists() and active_lines(target.read_text()) not in known_locks:
                raise ValueError('Existing FIDO2 lock service differs: left untouched')
            data = lock_config(mode).encode()
        else:
            source = target if target.exists() else safe_path(root, f'usr/lib/pam.d/{service}')
            if not source.is_file():
                raise ValueError(f'Missing PAM service: {service}')
            data = pam_with_key(source.read_text(), mode, fallback).encode()
        if not target.exists() or target.read_bytes() != data:
            changes[relative] = (data, 0o644)
    mapping = safe_path(root, 'etc/fido2/fido2')
    existing = mapping.read_text() if mapping.exists() else ''
    merged = merge_mapping(existing, enrollment, username).encode()
    if not mapping.exists() or mapping.read_bytes() != merged:
        changes['etc/fido2/fido2'] = (merged, 0o644)
    # Require root-only writes, even for an already configured mapping.
    if mapping.exists() and (mapping.stat().st_mode & 0o022 or (root == Path('/') and mapping.stat().st_uid != 0)):
        raise ValueError('Existing central mapping is not root-controlled; fix its ownership/permissions first')
    return changes


def write_atomic(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.yubikey-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore(root, backup, preserve_sync_state=True):
    base = safe_path(root, BACKUPS).resolve()
    backup = Path(backup)
    if backup.is_symlink():
        raise ValueError('Refusing symbolic-link backup')
    backup = backup.resolve()
    if backup.parent != base:
        raise ValueError('Rollback requires a backup directly inside the project backup directory')
    records = json.loads((backup / 'manifest.json').read_text())
    pending = []
    for record in records:
        if record['path'] not in TARGETS:
            raise ValueError('Unexpected target in backup manifest')
        if preserve_sync_state and record['path'] == 'var/lib/omarchy-yubikey/sync-state.json':
            continue
        target = safe_path(root, record['path'])
        if record['existed']:
            source = safe_path(backup, record['backup'])
            if not re.fullmatch(r'file-\d+', record['backup']):
                raise ValueError('Unexpected backup filename')
            pending.append((target, source.read_bytes(), record['mode'], record.get('uid'), record.get('gid')))
        else:
            pending.append((target, None, None, None, None))
    for target, data, mode, uid, gid in pending:
        if data is None:
            target.unlink(missing_ok=True)
        else:
            write_atomic(target, data, mode)
            if uid is not None and os.geteuid() == 0:
                os.chown(target, uid, gid)


def apply(root, changes):
    if not changes:
        return None
    backup = safe_path(root, BACKUPS / (datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]))
    backup.mkdir(parents=True, mode=0o700)
    # Backups may include enrollment data. Keep all parent directories private.
    for parent in (backup.parent, backup.parent.parent):
        parent.chmod(0o700)
    records = []
    for index, relative in enumerate(changes):
        target = safe_path(root, relative)
        record = {'path': relative, 'existed': target.exists()}
        if target.exists():
            original_stat = target.stat()
            record.update(backup=f'file-{index}', mode=stat.S_IMODE(original_stat.st_mode), uid=original_stat.st_uid, gid=original_stat.st_gid)
            write_atomic(backup / record['backup'], target.read_bytes(), 0o600)
        records.append(record)
    write_atomic(backup / 'manifest.json', (json.dumps(records, indent=2) + '\n').encode(), 0o600)
    try:
        for relative, (data, mode) in changes.items():
            if relative == 'etc/fido2/fido2':
                directory = safe_path(root, 'etc/fido2')
                if not directory.exists():
                    directory.mkdir()
                    directory.chmod(0o755)
            write_atomic(safe_path(root, relative), data, mode)
    except BaseException:
        restore(root, backup, preserve_sync_state=False)
        raise
    return backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='Alternate filesystem root for isolated tests')
    parser.add_argument('--user')
    parser.add_argument('--enrollment', type=Path)
    parser.add_argument('--services', nargs='+', choices=['sudo', 'polkit-1', 'omarchy-lock-fido2'])
    parser.add_argument('--apply', action='store_true', help='Write changes after a complete preflight')
    parser.add_argument('--auth-mode', choices=['pin', 'touch'], default='pin')
    parser.add_argument('--fallback', choices=['explicit', 'automatic'], default='explicit')
    parser.add_argument('--fallback-module', type=Path, help='Locally built PAM conversation gate')
    parser.add_argument('--rollback', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if (args.apply or args.rollback) and root == Path('/') and os.geteuid() != 0:
        parser.error('System changes require sudo')
    if args.rollback:
        with configuration_lock(root):
            restore(root, args.rollback)
        print('Previous PAM configuration restored.')
        return
    if not args.user or not args.enrollment or not args.services:
        parser.error('--user, --enrollment and --services are required')
    enrollment = args.enrollment.read_text()
    gate = args.fallback_module.read_bytes() if args.fallback_module else None
    changes = plan(root, args.services, enrollment, args.user, args.auth_mode, args.fallback, gate)
    if not changes:
        print('PAM and key enrollment are already configured.')
        return
    print('Planned changes (enrollment values are hidden):')
    print(f'  Key policy: {args.auth_mode}; password fallback: {args.fallback}')
    for relative in changes:
        print('  /' + relative)
    if not args.apply:
        print('Preview only; nothing written.')
        return
    with configuration_lock(root):
        changes = plan(root, args.services, enrollment, args.user, args.auth_mode, args.fallback, gate)
        backup = apply(root, changes)
    if backup is None:
        print('PAM and key enrollment are already configured.')
        return
    print(f'PAM configured. Backup: {backup}')
    print(f'Rollback: ./install.sh --rollback {backup.name}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f'Setup stopped: {error}', file=sys.stderr)
        sys.exit(1)
