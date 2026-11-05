#!/usr/bin/env python3
"""Read-only setup status and explicit terminal actions for the Omarchy plugin.

Only allowlisted operations can run. Authentication responses and child-process
output remain in the interactive terminal, never in JSON, GUI fields or logs.
"""
import argparse
from contextlib import contextmanager
import fcntl
import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[1]
BACKUP_ID = re.compile(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{8}')
ACTIONS = {
    'setup': 'Set up security-key authentication',
    'setup-sudo': 'Configure sudo authentication',
    'setup-desktop': 'Configure lock and desktop authorization',
    'setup-keyring': 'Set up the GNOME Keyring helper',
    'add-key': 'Enroll another security key without changing PAM policy',
    'remove-key': 'Remove one enrolled PAM security key',
    'test-sudo': 'Test sudo authentication',
    'desktop-restore': 'Return to the standard lock and Polkit plugins',
    'keyring-add': 'Add a backup key for GNOME Keyring',
    'keyring-check': 'Test GNOME Keyring password decryption',
    'keyring-unlock': 'Unlock GNOME Keyring',
    'keyring-enable': 'Enable GNOME Keyring unlock at graphical login',
    'keyring-disable': 'Disable GNOME Keyring unlock at graphical login',
    'luks-check': 'Check the selected LUKS2 device',
    'luks-enroll': 'Enroll a key for the selected LUKS2 device',
    'ssh-import': 'Copy the resident SSH keys of the security key into ~/.ssh',
    'ssh-remove': 'Remove one copied resident SSH key from ~/.ssh',
    'backups': 'List system PAM backup IDs',
    'rollback': 'Restore the selected PAM backup',
}


def ssh_status():
    """How many resident SSH key files ~/.ssh holds; never their names."""
    try:
        spec = importlib.util.spec_from_file_location('manage_ssh', SOURCE / 'scripts/manage-ssh.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        count = module.status().get('count')
    except (OSError, ValueError, ImportError):
        return {'count': 0}
    return {'count': count if isinstance(count, int) and 0 <= count <= 1000 else 0}


def bounded_text(path, limit=262144):
    with Path(path).open() as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError('File exceeds status limit')
    return value


def optional_text(path):
    try:
        return bounded_text(path)
    except FileNotFoundError:
        return ''


def capture(command, timeout=3):
    """Fixed local queries only. Never return captured stderr to the GUI."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode == 0 and len(result.stdout) <= 262144:
            return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def paths():
    home = Path.home()
    config = Path(os.environ.get('XDG_CONFIG_HOME') or home / '.config')
    state = Path(os.environ.get('XDG_STATE_HOME') or home / '.local/state')
    if not config.is_absolute() or not state.is_absolute():
        raise ValueError('XDG configuration/state directories must be absolute')
    store = Path(os.environ.get('KEYRING_UNLOCK_STORE') or config / 'keyring-unlock/password.json')
    if not store.is_absolute():
        raise ValueError('Keyring store must be an absolute path')
    return home, config, state, store


def pam_state(path):
    try:
        lines = [' '.join(line.split()) for line in optional_text(path).splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
    except (OSError, ValueError):
        return {'state': 'unreadable', 'pin': False, 'explicit': False}
    rules = [line for line in lines if line.startswith('auth ') and 'pam_u2f.so' in line]
    managed = [line for line in rules if all(token in line.split() for token in
               ('origin=pam://omarchy', 'appid=pam://omarchy', 'authfile=/etc/fido2/fido2'))]
    return {'state': 'configured' if managed else ('external' if rules else 'not-configured'),
            'pin': bool(managed) and all('pinverification=1' in line.split() for line in managed),
            'explicit': any(line == 'auth requisite /usr/local/lib/security/pam_omarchy_fallback.so' for line in lines)}


def enrolled_count(mapping, username):
    lines = [line for line in mapping.splitlines() if line.startswith(username + ':')]
    if len(lines) > 1:
        raise ValueError('Duplicate account entries')
    return len([item for item in lines[0].split(':')[1:] if item]) if lines else 0


def plugin_state(config, identity):
    path = config / 'omarchy/plugins' / identity / 'manifest.json'
    try:
        metadata = json.loads(bounded_text(path))
        return metadata.get('id') == identity
    except (OSError, ValueError):
        return False


def private_directory(state):
    directory = state / 'omarchy-yubikey/control-center'
    # Check every ancestor before creating anything; do not follow symlinks or
    # relax existing access permissions to make a status operation work.
    pending = []
    root_owner = Path("/").stat().st_uid
    current = directory
    while current != current.parent:
        if current.is_symlink():
            raise ValueError('Operation state paths must not be symlinks')
        if current.exists():
            info = current.stat()
            sticky_root = info.st_uid == root_owner and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_mode & 0o022 and not sticky_root) or info.st_uid not in (root_owner, os.getuid()):
                raise ValueError('Operation state paths must be owner-controlled')
        else:
            pending.append(current)
        current = current.parent
    for current in reversed(pending):
        current.mkdir(mode=0o700)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Operation state directory must be private (0700)')
    return directory


@contextmanager
def operation_lock(directory, wait_seconds=0):
    fd = os.open(directory / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Operation lock must be a private regular file')
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('Another YubiKey operation is already open in a terminal') from None
                time.sleep(0.05)
        yield


def save_operation(directory, value):
    target = directory / 'operation.json'
    if target.is_symlink():
        raise ValueError('Operation record must not be a symlink')
    fd, temporary = tempfile.mkstemp(prefix='.operation-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_operation(directory):
    target = directory / 'operation.json'
    if target.is_symlink():
        raise ValueError('Operation record must not be a symlink')
    try:
        value = json.loads(bounded_text(target, 4096))
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict) or value.get('action') not in ACTIONS:
        return {}
    if value.get('phase') not in ('starting', 'running', 'succeeded', 'failed', 'cancelled'):
        return {}
    return value


def operation_status(state):
    directory = state / 'omarchy-yubikey/control-center'
    if not directory.exists():
        return {}
    # Reading status never creates state directories or files.
    if directory.is_symlink() or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        return {'phase': 'unavailable'}
    value = read_operation(directory)
    if not value:
        return {}
    phase = value['phase']
    if phase == 'starting' and time.time() - value.get('time', 0) > 30:
        phase = 'interrupted'
    if phase == 'running':
        lock = directory / 'operation.lock'
        try:
            fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'r+') as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    phase = 'interrupted'
                except BlockingIOError:
                    pass
        except OSError:
            phase = 'interrupted'
    return {'action': value['action'], 'phase': phase}


def status(root=Path('/'), config=None, state=None, store=None, username=None, query=True):
    home, default_config, default_state, default_store = paths()
    config, state, store = config or default_config, state or default_state, store or default_store
    username = username or getpass.getuser()
    tools = {name: shutil.which(name) is not None for name in
             ('python3', 'pacman', 'pamu2fcfg', 'fido2-token', 'omarchy', 'omarchy-shell', 'cargo', 'cc',
              'cryptsetup', 'systemd-cryptenroll', 'ssh-keygen', 'gnome-keyring-daemon', 'omarchy-launch-terminal')}
    try:
        count = enrolled_count(optional_text(root / 'etc/fido2/fido2'), username)
        enrollment = {'state': 'enrolled' if count else 'not-enrolled', 'count': count}
    except (OSError, ValueError):
        enrollment = {'state': 'unreadable', 'count': 0}
    connected = None
    if query and tools['fido2-token']:
        listing = capture(['fido2-token', '-L'])
        if listing is not None:
            connected = len([line for line in listing.splitlines() if line.strip()])
    keyring = {'installed': (home / '.local/bin/keyring-unlock').is_file(), 'state': 'not-enrolled', 'count': 0,
               'unit': (config / 'systemd/user/keyring-unlock.service').is_file(), 'autostart': 'unknown'}
    try:
        value = json.loads(bounded_text(store))
        if value.get('version') != 1 or not isinstance(value.get('entries'), list):
            raise ValueError('Invalid helper store')
        keyring.update(state='enrolled', count=len(value['entries']))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError):
        keyring['state'] = 'unreadable'
    if query and shutil.which('systemctl'):
        enabled = capture(['systemctl', '--user', 'is-enabled', 'keyring-unlock.service'])
        keyring['autostart'] = 'enabled' if enabled and enabled.strip() == 'enabled' else 'disabled'
    plugins = {role: {'installed': plugin_state(config, 'yubikey.' + role), 'enabled': False}
               for role in ('lock', 'polkit')}
    if query and tools['omarchy-shell']:
        raw = capture(['omarchy-shell', 'shell', 'listPlugins'])
        try:
            listing = json.loads(raw or '[]')
            for item in listing:
                for role in plugins:
                    if item.get('id') == 'yubikey.' + role:
                        plugins[role]['enabled'] = item.get('enabled') is True
        except (ValueError, TypeError, AttributeError):
            pass
    sudo = pam_state(root / 'etc/pam.d/sudo')
    polkit = root / 'etc/pam.d/polkit-1'
    if not polkit.exists():
        polkit = root / 'usr/lib/pam.d/polkit-1'
    return {'schema': 1, 'ok': True, 'supported': tools['pacman'] and tools['omarchy'] and tools['omarchy-shell'],
            'tools': tools, 'connected': connected, 'enrollment': enrollment, 'sudo': sudo,
            'polkit': pam_state(polkit), 'lock': pam_state(root / 'etc/pam.d/omarchy-lock-fido2'),
            'plugins': plugins, 'keyring': keyring, 'ssh': ssh_status(), 'operation': operation_status(state)}


def command_plan(action, device='', backup=''):
    if action not in ACTIONS:
        raise ValueError('Unknown operation')
    if action.startswith('luks-'):
        if not re.fullmatch(r'/dev/[A-Za-z0-9_./:-]+', device) or '..' in Path(device).parts:
            raise ValueError('Select an explicit /dev/ block device')
    elif device:
        raise ValueError('Device is only valid for LUKS operations')
    if action == 'rollback':
        if not BACKUP_ID.fullmatch(backup):
            raise ValueError('Enter the backup ID printed by setup')
    elif backup:
        raise ValueError('Backup ID is only valid for rollback')
    install = ['bash', str(SOURCE / 'install.sh')]
    if action == 'setup':
        return [install]
    if action.startswith('setup-'):
        return [install + ['--components', action.removeprefix('setup-')]]
    if action in ('ssh-import', 'ssh-remove'):
        return [[sys.executable, str(SOURCE / 'scripts/manage-ssh.py'), action.removeprefix('ssh-')]]
    if action in ('add-key', 'remove-key'):
        return [[sys.executable, str(SOURCE / 'scripts/manage-keys.py'), 'add' if action == 'add-key' else 'remove']]
    if action == 'test-sudo':
        return [['sudo', '-k'], ['sudo', 'true']]
    if action == 'desktop-restore':
        _, config, _, _ = paths()
        commands = [['omarchy', 'plugin', 'disable', 'yubikey.' + role]
                    for role in ('lock', 'polkit') if plugin_state(config, 'yubikey.' + role)]
        if not commands:
            raise ValueError('No included authentication plugins are installed')
        return commands
    if action.startswith('keyring-') and action not in ('keyring-enable', 'keyring-disable'):
        binary = Path.home() / '.local/bin/keyring-unlock'
        if not binary.is_file() or binary.is_symlink() or binary.stat().st_uid != os.getuid() or binary.stat().st_mode & 0o022:
            raise ValueError('Set up the Keyring helper first')
        return [[str(binary), *({'keyring-add': ['enroll', '--add'], 'keyring-check': ['check'], 'keyring-unlock': ['unlock']}[action])]]
    if action in ('keyring-enable', 'keyring-disable'):
        _, config, _, _ = paths()
        unit = config / 'systemd/user/keyring-unlock.service'
        if unit.is_symlink() or not unit.is_file() or unit.read_bytes() != (SOURCE / 'systemd/keyring-unlock.service').read_bytes():
            raise ValueError('Install the reviewed login service through Keyring setup first')
        return [['systemctl', '--user', 'enable' if action == 'keyring-enable' else 'disable', 'keyring-unlock.service']]
    if action.startswith('luks-'):
        return [install + ['--luks', '--device', device] + (['--check'] if action == 'luks-check' else [])]
    if action == 'backups':
        return [['sudo', sys.executable, str(SOURCE / 'scripts/configure-pam.py'), '--list-backups']]
    if action == 'rollback':
        return [install + ['--rollback', backup]]
    raise ValueError('Unknown operation')


def unlocked():
    value = capture(['omarchy-shell', 'lock', 'isLocked'])
    return value is not None and value.strip() in ('false', 'no', '0')


def launch(action, device='', backup=''):
    command_plan(action, device, backup)  # Reject invalid input before opening a terminal.
    if os.geteuid() == 0:
        raise ValueError('Open the plugin as your normal desktop user')
    if not shutil.which('omarchy-launch-terminal'):
        raise ValueError('The Omarchy terminal launcher is unavailable')
    _, _, state, _ = paths()
    directory = private_directory(state)
    with operation_lock(directory):
        previous = read_operation(directory)
        if previous.get('phase') == 'starting' and time.time() - previous.get('time', 0) < 30:
            raise ValueError('The previous operation is still opening its terminal')
        ticket = uuid.uuid4().hex
        record = {'action': action, 'phase': 'starting', 'time': time.time(), 'ticket': ticket}
        save_operation(directory, record)
        command = ['omarchy-launch-terminal', sys.executable, str(Path(__file__).resolve()), 'run', action, '--ticket', ticket]
        if device:
            command += ['--device', device]
        if backup:
            command += ['--backup', backup]
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                if process.wait(timeout=0.3) != 0:
                    raise ValueError('The terminal launcher failed')
            except subprocess.TimeoutExpired:
                pass  # A terminal may remain attached for the complete operation.
        except (OSError, ValueError):
            record.update(phase='failed')
            save_operation(directory, record)
            raise ValueError('Could not open an interactive terminal') from None
    return {'ok': True}


def run(action, ticket, device='', backup=''):
    if os.geteuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('Operations require an interactive terminal and a normal desktop account')
    commands = command_plan(action, device, backup)
    _, _, state, _ = paths()
    directory = private_directory(state)
    with operation_lock(directory, wait_seconds=3):
        record = read_operation(directory)
        if not re.fullmatch(r'[0-9a-f]{32}', ticket or '') or record.get('ticket') != ticket or record.get('action') != action or record.get('phase') != 'starting' or time.time() - record.get('time', 0) > 30:
            raise ValueError('This operation request has expired; open it again from the plugin')
        print('\nOmarchy YubiKey — ' + ACTIONS[action] + '\n')
        if device:
            print('Selected device: ' + device)
        if backup:
            print('Selected backup: ' + backup)
        record.update(phase='running')
        save_operation(directory, record)
        print('PINs, passwords and recovery keys stay in this terminal. Do not record enrollment.')
        phase = 'failed'
        result = 1
        try:
            if input('Continue? [y/N] ').strip().lower() not in ('y', 'yes'):
                phase, result = 'cancelled', 0
            else:
                if action in ('setup-desktop', 'desktop-restore') and not unlocked():
                    raise ValueError('Unlock the desktop before changing authentication plugins')
                record.update(phase='running')
                save_operation(directory, record)
                for command in commands:
                    result = subprocess.call(command, cwd=SOURCE)
                    if result:
                        break
                phase = 'succeeded' if result == 0 else 'failed'
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled. Completed setup transactions may still need their printed rollback ID.')
            phase, result = 'cancelled', 1
        except (OSError, ValueError):
            print('Operation stopped. Keep your recovery terminal open and review the setup output.')
            result = 1
        finally:
            save_operation(directory, {'action': action, 'phase': phase, 'time': time.time()})
    try:
        input('\nPress Enter to close this terminal. ')
    except (EOFError, KeyboardInterrupt):
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    check = sub.add_parser('status', help='Read-only JSON inventory; no key touch or enrollment')
    check.add_argument('--root', type=Path, default=Path('/'), help='Filesystem root for isolated status tests')
    for mode in ('launch', 'run'):
        item = sub.add_parser(mode)
        item.add_argument('action', choices=sorted(ACTIONS))
        item.add_argument('--device', default='')
        item.add_argument('--backup', default='')
        if mode == 'run':
            item.add_argument('--ticket', required=True)
    args = parser.parse_args()
    try:
        if args.mode == 'status':
            print(json.dumps(status(root=args.root.resolve())))
        elif args.mode == 'launch':
            print(json.dumps(launch(args.action, args.device, args.backup)))
        else:
            return run(args.action, args.ticket, args.device, args.backup)
        return 0
    except (OSError, ValueError, TypeError):
        if args.mode == 'run':
            print('Operation unavailable. Reopen the plugin and check the prerequisites.', file=sys.stderr)
        else:
            print(json.dumps({'ok': False, 'error': 'Operation unavailable; check prerequisites or another open setup terminal.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
