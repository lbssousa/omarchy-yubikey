#!/usr/bin/env python3
"""Copy the resident SSH keys of a security key into ~/.ssh, or remove copies.

Interactive terminal operations, run as the desktop user without privileges:

  import  `ssh-keygen -K` in a private temporary directory, where ssh-keygen
          itself asks for the FIDO2 PIN, a touch and an optional passphrase;
          then each key file pair is moved into ~/.ssh, never over a file
          already there. Keys whose application names a git host
          (`ssh-keygen -O application=ssh:github.com`) can get a drop-in in
          ~/.ssh/config.d that uses them for that host without the SSH agent,
          optionally keeping the connection open for reuse (ControlPersist)
  remove  delete one copied key file pair from ~/.ssh, and its line in the
          drop-in made for it; the credential stays on the security key and
          can be imported again

`status()` is the metadata-only probe used by the control center: how many
resident key files ~/.ssh holds, without names.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

RESIDENT = re.compile(r'id_[a-z0-9]+_sk_rk[A-Za-z0-9_.:@-]*')
IMPORT_TIMEOUT = 180
# What follows the ssh: of an application: host, login@host or
# //login@host:port; the host needs at least one dot.
GIT_APPLICATION = re.compile(r'(?://)?(?:(?P<login>[A-Za-z0-9][A-Za-z0-9._-]*)@)?'
                      r'(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)'
                      r'(?::(?P<port>[0-9]{1,5}))?/?')
GIT_HOSTS = {'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'git.sr.ht',
             'gitea.com', 'ssh.dev.azure.com', 'vs-ssh.visualstudio.com'}
CONTROL_PERSIST_MINUTES = 15
MAX_PERSIST_MINUTES = 24 * 60
MARKER = '# Created by omarchy-yubikey for resident SSH keys.'
IDENTITY = '    IdentityFile ~/.ssh/'
INCLUDE = 'Include config.d/*.conf'


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


def application(directory, name):
    """The FIDO2 application of a key: ssh-keygen -K keeps it as the .pub comment."""
    try:
        fields = (directory / (name + '.pub')).read_text(errors='replace').split()
    except OSError:
        return None
    return fields[2] if len(fields) > 2 else None


def git_remote(value):
    """(login, host, port) when the application <value> names a git host, else None."""
    if not value or not value.startswith('ssh:'):
        return None
    match = GIT_APPLICATION.fullmatch(value[len('ssh:'):])
    if not match:
        return None
    host = match.group('host').lower()
    port = match.group('port')
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    labels = host.split('.')
    if host not in GIT_HOSTS and not any('git' in label for label in labels[:-1]):
        return None
    # Git hosts log in as git unless the application names another login.
    return match.group('login') or 'git', host, port


def key_remote(directory, name):
    """The git host a key was made for, from its application; the user ID is ignored."""
    return git_remote(application(directory, name))


def drop_in_text(names, remote, minutes):
    login, host, port = remote
    lines = [MARKER, 'Host ' + host, '    User ' + login]
    if port:
        lines.append('    Port ' + port)
    lines += [IDENTITY + name for name in names]
    lines += ['    IdentitiesOnly yes', '    IdentityAgent none']
    if minutes:
        lines += ['    ControlMaster auto', '    ControlPath ~/.ssh/control/%C',
                  '    ControlPersist ' + str(minutes) + 'm']
    return '\n'.join(lines) + '\n'


def write_drop_in(directory, names, remote, minutes):
    """Create ~/.ssh/config.d/<host>.conf; False when that file already exists."""
    config_d = directory / 'config.d'
    config_d.mkdir(mode=0o700, exist_ok=True)
    if config_d.is_symlink() or not config_d.is_dir():
        raise ValueError('~/.ssh/config.d must be a directory')
    if minutes:
        control = directory / 'control'
        control.mkdir(mode=0o700, exist_ok=True)
        if control.is_symlink() or not control.is_dir():
            raise ValueError('~/.ssh/control must be a directory')
    target = config_d / (remote[1] + '.conf')
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, 'w') as stream:
        stream.write(drop_in_text(names, remote, minutes))
    return True


def includes_drop_ins(config):
    try:
        lines = config.read_text(errors='replace').splitlines()
    except FileNotFoundError:
        return False
    return any(re.match(r'\s*include\s+\S*config\.d/', line, re.IGNORECASE) for line in lines)


def replace_text(path, text, mode):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def add_include(config):
    """Put the Include at the top of ~/.ssh/config, where it applies to every host."""
    if config.is_symlink():
        raise ValueError('~/.ssh/config is a symbolic link; add "' + INCLUDE + '" at its top yourself')
    try:
        text, mode = config.read_text(), stat.S_IMODE(config.stat().st_mode)
    except FileNotFoundError:
        text, mode = '', 0o600
    replace_text(config, INCLUDE + '\n' + ('\n' + text if text else ''), mode)


def drop_ins_for(directory, name):
    """Drop-ins this tool created that list ~/.ssh/<name>."""
    config_d = directory / 'config.d'
    if config_d.is_symlink() or not config_d.is_dir():
        return []
    found = []
    for path in sorted(config_d.glob('*.conf')):
        try:
            if path.is_file() and not path.is_symlink():
                lines = path.read_text(errors='replace').splitlines()
                if lines and lines[0] == MARKER and IDENTITY + name in lines:
                    found.append(path)
        except OSError:
            continue
    return found


def drop_key_from(path, name):
    """Remove the key's line; delete the drop-in when no key is left."""
    lines = path.read_text().splitlines()
    remaining = [line for line in lines if line != IDENTITY + name]
    if not any(line.startswith(IDENTITY) for line in remaining):
        path.unlink()
        return
    replace_text(path, '\n'.join(remaining) + '\n', stat.S_IMODE(path.stat().st_mode))


def ask_minutes():
    answer = input('Keep the connection open for reuse, in minutes (Enter for '
                   + str(CONTROL_PERSIST_MINUTES) + ', 0 for never): ').strip()
    if not answer:
        return CONTROL_PERSIST_MINUTES
    if not answer.isdecimal() or int(answer) > MAX_PERSIST_MINUTES:
        raise ValueError('Enter whole minutes from 0 to ' + str(MAX_PERSIST_MINUTES))
    return int(answer)


def git_hosts(directory, names):
    """{host: (remote, [names])} for the keys made for a git host."""
    hosts = {}
    for name in names:
        remote = key_remote(directory, name)
        if not remote:
            continue
        known, keys = hosts.setdefault(remote[1], (remote, []))
        if remote != known:
            print('~/.ssh/' + name + ' asks for ' + remote[0] + '@' + remote[1]
                  + ' while another key asks for ' + known[0] + '@' + known[1]
                  + '; only keys for the first are configured.')
            continue
        keys.append(name)
    return hosts


def offer_drop_ins(directory, names):
    """Ask, host by host, to configure the git hosts the keys were made for."""
    created = False
    for host, (remote, keys) in sorted(git_hosts(directory, names).items()):
        target = '~/.ssh/config.d/' + host + '.conf'
        if os.path.lexists(directory / 'config.d' / (host + '.conf')):
            print(target + ' already exists; it was left unchanged.')
            continue
        print('Keys for ' + remote[0] + '@' + host + ':')
        for name in keys:
            print('  ~/.ssh/' + name)
        if len(keys) > 1:
            print('ssh offers them in this order, and only the one ' + host
                  + ' accepts asks for a touch.')
        if input('Create ' + target + ' so ssh and git use ' + ('these keys' if len(keys) > 1 else 'this key')
                 + ' for ' + host + ', without the SSH agent? [y/N] ').strip().lower() not in ('y', 'yes'):
            continue
        minutes = ask_minutes()
        if minutes:
            print('While the connection stays open, new connections to ' + host
                  + ' reuse it without a PIN or touch.')
        if write_drop_in(directory, keys, remote, minutes):
            print('Created ' + target + '.')
            created = True
    config = directory / 'config'
    if created and not includes_drop_ins(config):
        if input('~/.ssh/config does not read ~/.ssh/config.d. Add "' + INCLUDE
                 + '" at its top? [y/N] ').strip().lower() in ('y', 'yes'):
            add_include(config)
            print('Added "' + INCLUDE + '" to ~/.ssh/config.')
        else:
            print('Add "' + INCLUDE + '" at the top of ~/.ssh/config for the drop-in to apply.')


def same_public_key(workdir, directory, name):
    try:
        return (workdir / (name + '.pub')).read_bytes() == (directory / (name + '.pub')).read_bytes()
    except OSError:
        return False


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
        directory = ssh_directory()
        imported, skipped = install(workdir, directory)
        # A kept copy of the very same key can be configured too.
        present = imported + [name for name in skipped if same_public_key(workdir, directory, name)]
    for name in imported:
        print('Imported ~/.ssh/' + name)
    for name in skipped:
        print('Kept the existing ~/.ssh/' + name + '; that key was not copied again.')
    offer_drop_ins(directory, sorted(present))


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
    drop_ins = drop_ins_for(directory, name)
    question = 'Remove ~/.ssh/' + name + ' and its .pub'
    if drop_ins:
        question += ', and its line in ' + ', '.join('~/.ssh/config.d/' + path.name for path in drop_ins)
    if input(question + '? [y/N] ').strip().lower() not in ('y', 'yes'):
        print('Cancelled; nothing changed.')
        return
    for path in (directory / name, directory / (name + '.pub')):
        if os.path.lexists(path):
            path.unlink()
    for path in drop_ins:
        drop_key_from(path, name)
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
