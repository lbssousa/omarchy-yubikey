#!/usr/bin/env python3
"""Import resident SSH key handles and manage explicitly selected Git hosts.

Runs as the desktop user. PINs and passphrases belong to ssh-keygen's terminal.
Public applications/fingerprints may enter the GUI; filenames and credential
handles never do. A removal reference identifies a particular pair, not a row.
"""
import argparse
import base64
from contextlib import contextmanager
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

RESIDENT = re.compile(r'id_[a-z0-9]+_sk_rk[A-Za-z0-9_.:@-]*')
KEY_ID = re.compile(r'[0-9a-f]{64}')
IMPORT_TIMEOUT = 180
FILE_LIMIT = 262144
STATUS_LIMIT = 50
GIT_APPLICATION = re.compile(r'(?://)?(?:(?P<login>[A-Za-z0-9][A-Za-z0-9._-]*)@)?'
                             r'(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)'
                             r'(?::(?P<port>[0-9]{1,5}))?/?')
GIT_HOSTS = {'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'git.sr.ht',
             'gitea.com', 'ssh.dev.azure.com', 'vs-ssh.visualstudio.com'}
CONTROL_PERSIST_MINUTES = 0
MAX_PERSIST_MINUTES = 1440
MANAGED = 'omarchy-yubikey/config'
INCLUDE = 'Include ' + MANAGED
MARKER = '# omarchy-yubikey-state-v1 '
# Construct the algorithm names without looking like personal email fixtures
# to the repository's publication check.
KEY_TYPES = {'sk-ssh-ed25519' + '@' + 'openssh.com': 'ed25519-sk',
             'sk-ecdsa-sha2-nistp256' + '@' + 'openssh.com': 'ecdsa-sk'}
PRIVATE_BEGIN = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'


def ssh_directory():
    return Path.home() / '.ssh'


def read_file(path, limit=FILE_LIMIT):
    """Read bounded, regular, user-owned files without following final symlinks."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Expected a regular file owned by your account')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('File exceeds the size limit')
        return data


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('SSH management directories must be owned by you and private (0700)')
    return path


@contextmanager
def operation_lock(directory):
    private_directory(directory)
    fd = os.open(directory / '.omarchy-yubikey.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Unsafe SSH management lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another SSH key operation is running') from None
        yield
    finally:
        os.close(fd)


def resident_keys(directory):
    try:
        return sorted(path.name for path in directory.iterdir()
                      if RESIDENT.fullmatch(path.name) and not path.name.endswith('.pub')
                      and not path.is_symlink() and path.is_file())
    except FileNotFoundError:
        return []


def ssh_string(data, offset):
    if offset + 4 > len(data):
        raise ValueError('Invalid SSH public key')
    length = int.from_bytes(data[offset:offset + 4], 'big')
    end = offset + 4 + length
    if length > FILE_LIMIT or end > len(data):
        raise ValueError('Invalid SSH public key')
    return data[offset + 4:end], end


def public_key(directory, name):
    fields = read_file(directory / (name + '.pub')).decode('ascii').split()
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ValueError('Not a security-key public key')
    blob = base64.b64decode(fields[1], validate=True)
    algorithm, at = ssh_string(blob, 0)
    if algorithm.decode('ascii') != fields[0]:
        raise ValueError('Public key algorithm mismatch')
    if KEY_TYPES[fields[0]] == 'ed25519-sk':
        point, at = ssh_string(blob, at)
        if len(point) != 32:
            raise ValueError('Invalid Ed25519 public key')
    else:
        curve, at = ssh_string(blob, at)
        point, at = ssh_string(blob, at)
        if curve != b'nistp256' or len(point) != 65 or point[:1] != b'\x04':
            raise ValueError('Invalid ECDSA public key')
    application, at = ssh_string(blob, at)
    if at != len(blob):
        raise ValueError('Trailing SSH public-key data')
    app = application.decode('utf-8')
    if not app.startswith('ssh:') or len(app) > 256 or not all(c.isprintable() and c.isascii() for c in app):
        app = ''
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return {'type': KEY_TYPES[fields[0]], 'application': app, 'fingerprint': fingerprint, 'blob': blob}


def key_reference(directory, name):
    public = public_key(directory, name)
    # Stable across row reordering; changes when either filename or public identity changes.
    return hashlib.sha256(name.encode() + b'\0' + public['blob']).hexdigest()


def private_header(path):
    """OpenSSH exposes the public half even when the private payload is encrypted."""
    text = read_file(path).decode('ascii')
    body = text.split(PRIVATE_BEGIN, 1)[1].split('-----END', 1)[0]
    data = base64.b64decode(''.join(body.split()), validate=True)
    magic = b'openssh-key-v1\0'
    if not data.startswith(magic):
        raise ValueError('Not an OpenSSH key handle')
    cipher, at = ssh_string(data, len(magic))
    _, at = ssh_string(data, at)  # KDF name
    _, at = ssh_string(data, at)  # KDF options
    if data[at:at + 4] != b'\0\0\0\1':
        raise ValueError('Expected exactly one key in the copied handle')
    blob, at = ssh_string(data, at + 4)
    payload, end = ssh_string(data, at)
    if not payload or end != len(data):
        raise ValueError('Invalid OpenSSH private envelope')
    return cipher, blob


def validate_pair(directory, name):
    public = public_key(directory, name)
    try:
        _, blob = private_header(directory / name)
    except (UnicodeError, IndexError) as error:
        raise ValueError('Invalid copied OpenSSH handle') from error
    if blob != public['blob']:
        raise ValueError('The private handle does not match its security-key public half')
    return public


def has_passphrase(path):
    try:
        cipher, _ = private_header(path)
        return cipher not in (b'none', b'')
    except (OSError, UnicodeError, IndexError, ValueError):
        return False


def application(directory, name):
    try:
        return public_key(directory, name)['application']
    except (OSError, UnicodeError, ValueError):
        return None


def git_remote(value):
    if not value or not value.startswith('ssh:'):
        return None
    match = GIT_APPLICATION.fullmatch(value[4:])
    if not match:
        return None
    host, port = match['host'].lower(), match['port']
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    if host not in GIT_HOSTS and not any('git' in label for label in host.split('.')[:-1]):
        return None
    return match['login'] or 'git', host, str(int(port)) if port else None


def drop_in_text(names, remote, minutes):
    login, host, port = remote
    lines = ['Host ' + host, '    User ' + login]
    if port:
        lines += ['    Port ' + port]
    lines += ['    IdentityFile ~/.ssh/' + name for name in sorted(names)]
    lines += ['    IdentitiesOnly yes', '    IdentityAgent none']
    if minutes:
        lines += ['    ControlMaster auto', '    ControlPath ~/.ssh/omarchy-yubikey/control/%C',
                  '    ControlPersist ' + str(minutes) + 'm']
    else:
        # ControlMaster no alone can still reuse a master at an inherited ControlPath.
        lines += ['    ControlMaster no', '    ControlPath none', '    ControlPersist no']
    return '\n'.join(lines) + '\n'


def managed_text(hosts):
    state = json.dumps({'schema': 1, 'hosts': hosts}, sort_keys=True, separators=(',', ':'))
    header = MARKER + base64.b64encode(state.encode()).decode() + '\n'
    return header + ''.join(drop_in_text(entry['names'], tuple(entry['remote']), entry['minutes']) + '\n'
                            for _, entry in sorted(hosts.items()))


def load_managed(directory):
    """The one atomically replaced file carries its own bounded source model.

    Comparing its complete rendering detects hand edits without a two-file
    config/manifest transaction that can be interrupted between replacements.
    """
    try:
        text = read_file(directory / MANAGED).decode('utf-8')
    except FileNotFoundError:
        return {}, '', False
    try:
        first = text.splitlines()[0]
        if not first.startswith(MARKER):
            raise ValueError()
        state = json.loads(base64.b64decode(first[len(MARKER):], validate=True))
        if state['schema'] != 1 or not isinstance(state['hosts'], dict) or len(state['hosts']) > 100:
            raise ValueError()
        hosts = state['hosts']
        for host, entry in hosts.items():
            remote, names, minutes = entry['remote'], entry['names'], entry['minutes']
            if not isinstance(remote, list) or len(remote) != 3 or remote[1] != host:
                raise ValueError()
            value = 'ssh:' + remote[0] + '@' + host + (':' + remote[2] if remote[2] else '')
            if tuple(remote) != git_remote(value):
                raise ValueError()
            if not isinstance(names, list) or not names or len(names) > 1000 or len(set(names)) != len(names):
                raise ValueError()
            if any(not isinstance(name, str) or not RESIDENT.fullmatch(name) or name.endswith('.pub') for name in names):
                raise ValueError()
            if type(minutes) is not int or not 0 <= minutes <= MAX_PERSIST_MINUTES:
                raise ValueError()
        return hosts, text, text != managed_text(hosts)
    except (KeyError, TypeError, IndexError, UnicodeError, ValueError):
        raise ValueError('The managed SSH file has no valid management header; move it aside before continuing') from None


def status():
    directory = ssh_directory()
    names = resident_keys(directory)
    try:
        hosts, _, modified = load_managed(directory)
    except (OSError, ValueError):
        hosts, modified = {}, True
    try:
        main, _ = config_text(directory)
        enabled = include_text(main) == main
    except (OSError, ValueError, UnicodeError):
        enabled = False
    configured = {name for entry in hosts.values() for name in entry['names']} if not modified and enabled else set()
    keys = []
    for name in names:
        try:
            public = validate_pair(directory, name)
            reference = key_reference(directory, name)
            read_file(directory / name)
        except (OSError, UnicodeError, ValueError):
            continue
        keys.append({key: public[key] for key in ('type', 'application', 'fingerprint')})
        keys[-1].update(id=reference, passphrase=has_passphrase(directory / name), host=name in configured)
        if len(keys) == STATUS_LIMIT:
            break
    return {'count': len(names), 'keys': keys, 'modified': modified}


def replace_text(path, text, mode=0o600, expected=None):
    """Atomic replacement, refusing symlinks and changes since the reviewed read."""
    if path.is_symlink():
        raise ValueError('Refusing a symbolic link destination')
    if expected is not None:
        try:
            current = read_file(path).decode('utf-8')
        except FileNotFoundError:
            current = ''
        if current != expected:
            raise ValueError('SSH configuration changed during review; try again')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def config_text(directory):
    config = directory / 'config'
    try:
        text = read_file(config).decode('utf-8')
        mode = stat.S_IMODE(config.stat().st_mode)
        if mode & 0o022:
            raise ValueError('SSH config must not be writable by other accounts')
        return text, mode
    except FileNotFoundError:
        return '', 0o600


def include_text(text, include=INCLUDE):
    # Always own one canonical global Include, irrespective of unrelated or
    # conditional Include directives. Do not try to parse OpenSSH's grammar.
    remaining = text
    if remaining.startswith(INCLUDE + '\n'):
        remaining = remaining[len(INCLUDE) + 1:]
        if remaining.startswith('\n'):
            remaining = remaining[1:]
    remaining = ''.join(line for line in remaining.splitlines(True) if line.strip() != INCLUDE)
    return include + '\n' + ('\n' + remaining if remaining else '')


def ssh_options(config, host):
    result = subprocess.run(['ssh', '-G', '-F', str(config), host], capture_output=True,
                            text=True, timeout=10, check=False)
    if result.returncode:
        raise ValueError('OpenSSH rejected the proposed configuration; no configuration was written')
    keys = {'user', 'hostname', 'port', 'identityfile', 'identityagent', 'identitiesonly',
            'controlmaster', 'controlpath', 'controlpersist'}
    return [line for line in result.stdout.splitlines() if line.partition(' ')[0] in keys]


def preview(directory, hosts, proposed, main):
    """Ask OpenSSH itself to resolve settings, including existing Host/Match rules."""
    with tempfile.TemporaryDirectory(prefix='.yubikey-preview-', dir=directory) as tmp:
        at = Path(tmp)
        managed = at / 'managed'
        managed.write_text(proposed)
        # Quote paths for OpenSSH, including spaces in account home directories.
        path = str(managed).replace('\\', '\\\\').replace('"', '\\"')
        candidate = at / 'config'
        candidate.write_text(include_text(main, 'Include "' + path + '"'))
        original = at / 'original'
        original.write_text(main)
        for host, entry in sorted(hosts.items()):
            before, after = ssh_options(original, host), ssh_options(candidate, host)
            required = {'user ' + entry['remote'][0], 'identityagent none', 'identitiesonly yes'}
            if entry['remote'][2]:
                required.add('port ' + entry['remote'][2])
            if not entry['minutes']:
                required.add('controlmaster false')
                # OpenSSH omits ControlPath when its value is none.
                if any(line.startswith('controlpath ') for line in after):
                    raise ValueError('An inherited SSH control socket is still active; no configuration was written')
            if not required <= set(after):
                raise ValueError('Existing SSH rules conflict with the requested settings; no configuration was written')
            print('Effective SSH settings for ' + host + ':')
            print(''.join(difflib.unified_diff([x + '\n' for x in before], [x + '\n' for x in after],
                                             fromfile='current', tofile='proposed')) or '  unchanged')


def save_hosts(directory, hosts, previous, modified=False):
    proposed = managed_text(hosts)
    if proposed == previous and not modified:
        return
    main, mode = config_text(directory)
    print(''.join(difflib.unified_diff(previous.splitlines(True)[1:], proposed.splitlines(True)[1:],
                                     fromfile=MANAGED + ' current', tofile=MANAGED + ' proposed')))
    preview(directory, hosts, proposed, main)
    answer = input('Replace the manually edited managed file? Type REPLACE: ' if modified
                   else 'Apply these SSH configuration changes? [y/N] ').strip()
    accepted = answer == 'REPLACE' if modified else answer.lower() in ('y', 'yes')
    if not accepted:
        print('SSH configuration left unchanged.')
        return False
    managed_dir = private_directory(directory / 'omarchy-yubikey')
    if any(entry['minutes'] for entry in hosts.values()):
        private_directory(managed_dir / 'control')
    new_main = include_text(main)
    # First install the complete managed file; only then enable its Include.
    # If enabling fails, it is safe to repeat: the next run still offers the Include.
    replace_text(directory / MANAGED, proposed, expected=previous)
    if new_main != main:
        replace_text(directory / 'config', new_main, mode, expected=main)
    return True


def ask_minutes():
    answer = input('Connection reuse in minutes (Enter or 0: authenticate each new connection; maximum 1440): ').strip()
    if not answer:
        return CONTROL_PERSIST_MINUTES
    if not re.fullmatch(r'[0-9]{1,4}', answer) or int(answer) > MAX_PERSIST_MINUTES:
        raise ValueError('Enter whole minutes from 0 to 1440')
    return int(answer)


def offer_drop_ins(directory, names):
    hosts, previous, modified = load_managed(directory)
    hosts = json.loads(json.dumps(hosts))
    present = set(resident_keys(directory))
    # Drop stale references when explicitly applying the next reviewed update.
    hosts = {host: dict(entry, names=[n for n in entry['names'] if n in present])
             for host, entry in hosts.items()}
    hosts = {host: entry for host, entry in hosts.items() if entry['names']}
    grouped = {}
    for name in names:
        remote = git_remote(application(directory, name))
        if remote:
            grouped.setdefault(remote[1], []).append((remote, name))
    for host, candidates in sorted(grouped.items()):
        old = hosts.get(host)
        remote = tuple(old['remote']) if old else candidates[0][0]
        matching = [name for candidate, name in candidates if candidate == remote]
        if len(matching) != len(candidates):
            print('Different logins or ports for ' + host + '; conflicting keys are not configured.')
        if not matching:
            continue
        added = sorted(set(matching) | set(old['names'] if old else []))
        if old and added == old['names']:
            continue
        print('Keys for ' + host + ': ' + ', '.join(matching))
        if input('Configure these keys for ' + host + ' without the SSH agent? [y/N] ').strip().lower() not in ('y', 'yes'):
            continue
        minutes = old['minutes'] if old else ask_minutes()
        if minutes:
            print('Connections reuse the authenticated session for ' + str(minutes)
                  + ' minutes without another PIN or touch; removal does not close an existing session.')
        hosts[host] = {'remote': list(remote), 'names': added, 'minutes': minutes}
    # A previous run may have written the managed file but failed before enabling
    # its global Include. Offer to finish that step even without new keys.
    main, _ = config_text(directory)
    if hosts and (managed_text(hosts) != previous or include_text(main) != main or modified):
        if managed_text(hosts) == previous and include_text(main) != main:
            preview(directory, hosts, previous, main)
            if input('Enable the managed SSH configuration globally? [y/N] ').strip().lower() in ('y', 'yes'):
                text, mode = config_text(directory)
                if text != main:
                    raise ValueError('SSH config changed during review')
                replace_text(directory / 'config', include_text(main), mode, expected=main)
            return
        save_hosts(directory, hosts, previous, modified)


def copy_exclusive(source, target, mode):
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(read_file(source))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def install(workdir, directory):
    private_directory(directory)
    imported, skipped = [], []
    for name in resident_keys(workdir):
        validate_pair(workdir, name)  # Require a matching SK pair before touching the destination.
        pair = [(name, 0o600), (name + '.pub', 0o644)]
        if any(os.path.lexists(directory / item) for item, _ in pair):
            skipped.append(name)
            continue
        written = []
        try:
            for item, mode in pair:
                copy_exclusive(workdir / item, directory / item, mode)
                written.append(directory / item)
        except BaseException as error:
            for path in written:
                path.unlink(missing_ok=True)
            if isinstance(error, FileExistsError):
                skipped.append(name)
                continue
            raise
        imported.append(name)
    return imported, skipped


def do_import():
    runtime = os.environ.get('XDG_RUNTIME_DIR')
    base = runtime if runtime and os.path.isdir(runtime) else None
    print('ssh-keygen asks for the FIDO2 PIN, touch and a passphrase for the copied handles.')
    with tempfile.TemporaryDirectory(prefix='omarchy-yubikey-ssh-', dir=base) as temporary:
        workdir = Path(temporary)
        result = subprocess.call(['ssh-keygen', '-K'], cwd=workdir, timeout=IMPORT_TIMEOUT)
        if result:
            raise ValueError('ssh-keygen did not finish; no downloaded keys were installed')
        if not resident_keys(workdir):
            print('No resident SSH keys found.')
            return
        directory = ssh_directory()
        imported, skipped = install(workdir, directory)
        present = list(imported)
        for name in skipped:
            try:
                if public_key(workdir, name)['blob'] == public_key(directory, name)['blob']:
                    present.append(name)
            except (OSError, ValueError):
                pass
    for name in imported:
        print('Imported ~/.ssh/' + name)
    for name in skipped:
        print('Kept existing ~/.ssh/' + name)
    offer_drop_ins(directory, sorted(present))


def do_remove(key_id=None):
    directory = ssh_directory()
    names = resident_keys(directory)
    if not names:
        if key_id:
            raise ValueError('The selected key is gone; refresh the control center')
        print('No resident key copies found.')
        return
    if key_id:
        if not KEY_ID.fullmatch(key_id):
            raise ValueError('Invalid key reference')
        matches = []
        for name in names:
            try:
                if key_reference(directory, name) == key_id:
                    matches.append(name)
            except (OSError, ValueError):
                continue
        if len(matches) != 1:
            raise ValueError('The selected key changed or is gone; refresh the control center')
        name = matches[0]
    else:
        for i, name in enumerate(names, 1):
            print(str(i) + '. ' + name)
        selected = input('Number to remove, or Enter to cancel: ').strip()
        if not selected:
            return
        if not selected.isdecimal() or not 1 <= int(selected) <= len(names):
            raise ValueError('Invalid selection')
        name = names[int(selected) - 1]
    # Snapshot the exact two files before asking; never retarget a stale selection.
    before = {suffix: read_file(directory / (name + suffix)) for suffix in ('', '.pub')}
    public = validate_pair(directory, name)
    reference = key_reference(directory, name)
    print('Selected ' + public['fingerprint'] + ' (' + public['application'] + ')')
    print('Only the copied handle is removed. The credential stays on the key. Existing SSH sessions remain open.')
    if input('Remove ~/.ssh/' + name + ' and its .pub? [y/N] ').strip().lower() not in ('y', 'yes'):
        return
    hosts, previous, modified = load_managed(directory)
    updated = {host: dict(entry, names=[n for n in entry['names'] if n != name]) for host, entry in hosts.items()}
    updated = {host: entry for host, entry in updated.items() if entry['names']}
    if updated != hosts or modified:
        if not save_hosts(directory, updated, previous, modified):
            print('Key files left unchanged.')
            return
    if key_reference(directory, name) != reference or any(
            read_file(directory / (name + suffix)) != data for suffix, data in before.items()):
        raise ValueError('The key files changed during confirmation; no key files were removed')
    for suffix in ('', '.pub'):
        (directory / (name + suffix)).unlink()
    print('Removed ~/.ssh/' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['import', 'remove'])
    parser.add_argument('--key-id', help='stable opaque reference returned by status')
    args = parser.parse_args()
    if args.key_id and (args.operation != 'remove' or not KEY_ID.fullmatch(args.key_id)):
        parser.error('--key-id requires a removal reference of 64 hexadecimal characters')
    if os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error('Run as the desktop user in an interactive terminal')
    with operation_lock(ssh_directory()):
        do_import() if args.operation == 'import' else do_remove(args.key_id)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError, EOFError, KeyboardInterrupt) as error:
        print('SSH key operation stopped: ' + (str(error) or 'cancelled'), file=sys.stderr)
        raise SystemExit(1)
