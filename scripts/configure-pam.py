#!/usr/bin/env python3
"""Conservative Arch PAM configuration with versioned backups and rollback."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n import tr

AUTH = 'auth sufficient pam_u2f.so cue origin=pam://omarchy appid=pam://omarchy authfile=/etc/fido2/fido2'
LOCK = '#%PAM-1.0\nauth required pam_u2f.so origin=pam://omarchy appid=pam://omarchy authfile=/etc/fido2/fido2\naccount include system-local-login\n'
GATE = 'usr/local/lib/security/pam_omarchy_fallback.so'
GATE_AUTH = 'auth requisite /' + GATE
TARGETS = {'etc/pam.d/sudo', 'etc/pam.d/polkit-1', 'etc/pam.d/omarchy-lock-fido2', 'etc/fido2/fido2', GATE, 'var/lib/omarchy-yubikey/sync-state.json'}
BACKUPS = Path('var/lib/omarchy-yubikey/backups')


def key_auth(mode='pin'):
    if mode not in ('pin', 'touch'):
        raise ValueError(tr('Unsupported authentication mode'))
    return AUTH + (' pinverification=1 userpresence=1' if mode == 'pin' else ' userpresence=1')


def lock_config(mode='pin'):
    return LOCK.replace('authfile=/etc/fido2/fido2', 'authfile=/etc/fido2/fido2' +
                        (' pinverification=1 userpresence=1' if mode == 'pin' else ' userpresence=1'))


def safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError(tr('Unsafe configuration path'))
    path = root / relative
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError(tr('Refusing symbolic link: %1', parent))
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
            raise ValueError(tr('Configuration directories must be root-controlled'))
    path = safe_path(root, 'var/lib/omarchy-yubikey/config.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or (root == Path('/') and info.st_uid != 0):
            raise ValueError(tr('Configuration lock must be a root-controlled regular file'))
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
        raise ValueError(tr('Custom PAM authentication stack: left untouched. Use docs/pam-setup.md for manual review.'))
    if fallback not in ('explicit', 'automatic'):
        raise ValueError(tr('Unsupported fallback policy'))
    desired = [key_auth(mode)] + ([GATE_AUTH] if fallback == 'explicit' else [])
    original = [line for line in text.splitlines(keepends=True)
                if not re.match(r'^\s*auth\s+', line) or ' '.join(line.split()) == 'auth include system-auth']
    index = next(i for i, line in enumerate(original) if re.match(r'^\s*auth\s+', line))
    original[index:index] = [line + '\n' for line in desired]
    return ''.join(original)


def merge_mapping(existing, enrollment, username):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\$?', username):
        raise ValueError(tr('Unsupported account name'))
    entry = enrollment.strip()
    if '\n' in entry or '\r' in entry or not entry.startswith(username + ':'):
        raise ValueError(tr('Enrollment must contain one line for the selected user'))
    added = entry.split(':')[1:]
    if not added or any(not item or ',' not in item or re.search(r'\s', item) for item in added):
        raise ValueError(tr('Enrollment is empty or malformed'))
    lines = existing.splitlines()
    matches = [i for i, line in enumerate(lines) if line.startswith(username + ':')]
    if len(matches) > 1:
        raise ValueError(tr('Duplicate user entries in existing mapping: merge manually first'))
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


def plan(root, services, enrollment, username, mode='pin', fallback='explicit', gate=None,
         allow_shared_policy_change=False):
    changes = {}
    key_auth(mode)  # Validate even when only the lock is selected.
    if fallback not in ('explicit', 'automatic'):
        raise ValueError(tr('Unsupported fallback policy'))
    if fallback == 'explicit' and any(s in ('sudo', 'polkit-1') for s in services):
        target = safe_path(root, GATE)
        if gate is not None:
            if not gate.startswith(b'\x7fELF'):
                raise ValueError(tr('Build the fallback PAM module first'))
            if not target.exists() or target.read_bytes() != gate:
                changes[GATE] = (gate, 0o644)
        elif not target.is_file():
            raise ValueError(tr('Explicit fallback needs --fallback-module built by scripts/build-pam-gate.sh'))
        if target.exists() and (target.stat().st_mode & 0o022 or (root == Path('/') and target.stat().st_uid != 0)):
            raise ValueError(tr('Fallback module must be root-controlled'))
    for service in services:
        relative = f'etc/pam.d/{service}'
        target = safe_path(root, relative)
        if service == 'omarchy-lock-fido2':
            if not safe_path(root, 'etc/pam.d/omarchy-lock-password').is_file():
                raise ValueError(tr('The shell password-lock PAM service is missing; desktop setup was not changed'))
            known_locks = [active_lines(item) for item in (LOCK, lock_config('pin'), lock_config('touch'))]
            if target.exists() and active_lines(target.read_text()) not in known_locks:
                raise ValueError(tr('Existing FIDO2 lock service differs: left untouched'))
            data = lock_config(mode).encode()
        else:
            source = target if target.exists() else safe_path(root, f'usr/lib/pam.d/{service}')
            if not source.is_file():
                raise ValueError(tr('Missing PAM service: %1', service))
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
        raise ValueError(tr('Existing central mapping is not root-controlled; fix its ownership/permissions first'))
    other_accounts = any(line.strip() and not line.lstrip().startswith('#')
                         and line.split(':', 1)[0] != username for line in existing.splitlines())
    if other_accounts and not allow_shared_policy_change and any(name.startswith('etc/pam.d/') for name in changes):
        raise ValueError(tr('PAM policy is shared with other enrolled accounts. Keep the existing policy or explicitly use --allow-shared-policy-change after reviewing its effect on every account.'))
    return changes


def key_references(mapping, username):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*\$?', username):
        raise ValueError(tr('Unsupported account name'))
    rows = [line for line in mapping.splitlines() if line.startswith(username + ':')]
    if len(rows) > 1:
        raise ValueError(tr('Duplicate user entries in existing mapping: merge manually first'))
    credentials = rows[0].split(':')[1:] if rows else []
    if rows and (not credentials or any(not item or ',' not in item or re.search(r'\s', item) for item in credentials)):
        raise ValueError(tr('Enrollment is empty or malformed'))
    return [hashlib.sha256(item.encode()).hexdigest() for item in credentials]


def remove_key_plan(root, username, reference):
    if not re.fullmatch(r'[0-9a-f]{64}', reference):
        raise ValueError('Choose one complete key reference from the management screen')
    target = safe_path(root, 'etc/fido2/fido2')
    info = target.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or (root == Path('/') and info.st_uid != 0):
        raise ValueError('Central enrollment must be a root-controlled regular file')
    text = target.read_text()
    references = key_references(text, username)
    if references.count(reference) != 1:
        raise ValueError('Key reference is missing or ambiguous; refresh the list before removing')
    if len(references) <= 1:
        raise ValueError('The last enrolled key cannot be removed here; keep a working recovery key')
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(username + ':'):
            entries = line.split(':')[1:]
            entries.pop(references.index(reference))
            lines[i] = username + ':' + ':'.join(entries)
    return {'etc/fido2/fido2': (('\n'.join(lines) + '\n').encode(), 0o644)}


def list_backups(root):
    directory = safe_path(root, BACKUPS)
    if not directory.exists():
        print('No system PAM backups found.')
        return
    for path in sorted(directory.iterdir(), reverse=True):
        if path.is_symlink() or not path.is_dir() or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{8}', path.name):
            continue
        manifest = safe_path(root, path.relative_to(root) / 'manifest.json')
        records = json.loads(manifest.read_text())
        if not isinstance(records, list) or any(not isinstance(record, dict) or record.get('path') not in TARGETS for record in records):
            raise ValueError('Unexpected backup manifest; review locally')
        print(path.name + ' — ' + ', '.join('/' + record['path'] for record in records))


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
        raise ValueError(tr('Refusing symbolic-link backup'))
    backup = backup.resolve()
    if backup.parent != base:
        raise ValueError(tr('Rollback requires a backup directly inside the project backup directory'))
    records = json.loads((backup / 'manifest.json').read_text())
    pending = []
    for record in records:
        if record['path'] not in TARGETS:
            raise ValueError(tr('Unexpected target in backup manifest'))
        if preserve_sync_state and record['path'] == 'var/lib/omarchy-yubikey/sync-state.json':
            continue
        target = safe_path(root, record['path'])
        if preserve_sync_state:
            if 'applied_sha256' not in record or 'applied_mode' not in record:
                raise ValueError(tr('Legacy backup has no rollback conflict checks. Review and restore it manually; automatic rollback could remove another account enrollment.'))
            current = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
            mode_changed = target.exists() and stat.S_IMODE(target.stat().st_mode) != record.get('applied_mode')
            if current != record['applied_sha256'] or mode_changed:
                raise ValueError(tr('Configuration changed after this backup. Automatic rollback was stopped before writing; preserve later account enrollments and review the backup manually.'))
        if record['existed']:
            source = safe_path(backup, record['backup'])
            if not re.fullmatch(r'file-\d+', record['backup']):
                raise ValueError(tr('Unexpected backup filename'))
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
        record = {'path': relative, 'existed': target.exists(),
                  'applied_sha256': hashlib.sha256(changes[relative][0]).hexdigest(),
                  'applied_mode': changes[relative][1]}
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
    parser.add_argument('--language', help='Override the Omarchy display language')
    parser.add_argument('--root', type=Path, default=Path('/'), help='Alternate filesystem root for isolated tests')
    parser.add_argument('--user')
    parser.add_argument('--enrollment', type=Path)
    parser.add_argument('--services', nargs='+', choices=['sudo', 'polkit-1', 'omarchy-lock-fido2'])
    parser.add_argument('--apply', action='store_true', help='Write changes after a complete preflight')
    parser.add_argument('--auth-mode', choices=['pin', 'touch'], default='pin')
    parser.add_argument('--fallback', choices=['explicit', 'automatic'], default='explicit')
    parser.add_argument('--fallback-module', type=Path, help='Locally built PAM conversation gate')
    parser.add_argument('--allow-shared-policy-change', action='store_true',
                        help='Explicitly allow PAM policy changes affecting other enrolled accounts')
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('--rollback', type=Path)
    operation.add_argument('--enrollment-only', action='store_true', help='Merge this account enrollment without changing PAM policy')
    operation.add_argument('--remove-key', help='Full SHA-256 key reference; changes enrollment only')
    operation.add_argument('--list-backups', action='store_true', help='List backup IDs and affected paths without credential contents')
    args = parser.parse_args()
    root = args.root.resolve()
    if (args.apply or args.rollback or args.list_backups) and root == Path('/') and os.geteuid() != 0:
        parser.error(tr('System changes require sudo'))
    if args.list_backups:
        list_backups(root)
        return
    if args.rollback:
        with configuration_lock(root):
            restore(root, args.rollback)
        print(tr('Previous PAM configuration restored.'))
        return
    if not args.user:
        parser.error('--user is required')
    if (args.enrollment_only or args.remove_key) and args.services:
        parser.error('Enrollment-only operations cannot change service policy')
    if args.remove_key:
        def make_plan():
            return remove_key_plan(root, args.user, args.remove_key)
    else:
        if not args.enrollment or (not args.enrollment_only and not args.services):
            parser.error(tr('--user, --enrollment and --services are required'))
        enrollment = args.enrollment.read_text()
        gate = args.fallback_module.read_bytes() if args.fallback_module else None
        def make_plan():
            return plan(root, args.services or [], enrollment, args.user, args.auth_mode, args.fallback, gate,
                        args.allow_shared_policy_change)
    changes = make_plan()
    if not changes:
        print(tr('PAM and key enrollment are already configured.'))
        return
    print(tr('Planned changes (enrollment values are hidden):'))
    if args.enrollment_only or args.remove_key:
        print('  Enrollment only; shared PAM policy is unchanged.')
    else:
        print(tr('  Key policy: %1; password fallback: %2', args.auth_mode, args.fallback))
    for relative in changes:
        print('  /' + relative)
    if not args.apply:
        print(tr('Preview only; nothing written.'))
        return
    with configuration_lock(root):
        changes = make_plan()
        backup = apply(root, changes)
    if backup is None:
        print(tr('PAM and key enrollment are already configured.'))
        return
    print(tr('PAM configured. Backup: %1', backup))
    print(tr('Rollback: ./install.sh --rollback %1', backup.name))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(tr('Setup stopped: %1', error), file=sys.stderr)
        sys.exit(1)
