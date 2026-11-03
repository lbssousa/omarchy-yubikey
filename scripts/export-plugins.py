#!/usr/bin/env python3
"""Export the two shell plugins into standalone Omarchy plugin repositories."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
SUITE = 'https://github.com/marselnenaj/omarchy-yubikey'
FILES = {'lock': ['Service.qml', 'LockView.qml'], 'polkit': ['PolkitAgent.qml', 'PolkitModel.js']}


def export(role, output):
    source = ROOT / 'plugins' / f'yubikey.{role}'
    manifest = json.loads((source / 'manifest.json').read_text())
    version = manifest['version']
    tag = 'v' + version
    name = f'omarchy-yubikey-{role}'
    destination = output / name
    if destination.exists():
        raise ValueError(f'Refusing to overwrite {destination}')
    destination.mkdir(parents=True)
    exported = ['manifest.json', *FILES[role]]
    for filename in exported:
        path = source / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected a regular plugin source file')
        shutil.copy2(path, destination / filename)
    for filename in ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md']:
        shutil.copy2(ROOT / filename, destination / filename)
    provenance = {
        'repository': SUITE,
        'ref': tag,
        'sourceDirectory': f'plugins/yubikey.{role}',
        'sha256': {filename: hashlib.sha256((destination / filename).read_bytes()).hexdigest() for filename in exported},
    }
    (destination / 'SOURCE.json').write_text(json.dumps(provenance, indent=2) + '\n')
    details = (
        'A theme-aware session lock with separate FIDO2, password and optional fingerprint PAM flows.\n'
        'The password field remains available while the key flow waits for a touch.'
        if role == 'lock' else
        'A theme-aware Polkit agent that shows a touch prompt while PAM waits for a security key,\n'
        'with fingerprint and password prompts when those methods are requested.'
    )
    readme = f'''# {manifest['name']}

{details}

**Version {version}.** This standalone plugin comes from
[Omarchy YubiKey]({SUITE}), which also provides guided key enrollment and PAM
configuration. See the suite release notes for validation and compatibility.

## Requirements

Omarchy 4 with its Quickshell plugin host, `qs.Commons`, `qs.Ui`, the PAM/Polkit
modules and authentication-clone support. The source environment used Omarchy
4.0.6. Other shell versions are unqualified. This is trusted authentication
code that runs inside the shell; review it before enabling it.

The lock needs the shell's existing `omarchy-lock-password` PAM service. For key
unlock it also needs `omarchy-lock-fido2` and a central enrollment mapping.
Polkit needs the matching key authentication rule in `/etc/pam.d/polkit-1`.
[Guided setup and recovery]({SUITE}/blob/{tag}/docs/install.md) configures those
pieces with backups. Installing this plugin alone does not alter PAM or enroll
a key, and it does not install the optional Keyring helper.

## Install

Use the suite's guided installer if you want the full setup. To install just
this shell plugin after configuring PAM:

```sh
omarchy plugin add https://github.com/marselnenaj/{name}.git
omarchy plugin enable yubikey.{role}
```

Enable it while the desktop is unlocked. Disable any other custom replacement
for `omarchy.{role}` first; keep a recovery terminal available. The host uses
`omarchy.clonedFrom` to replace the stock service. Do not mix a Git-managed copy
with a directory already copied by the suite installer under the same ID.
Test key and password authentication before relying on it. Plugin commands
follow the repository's default branch; use the suite release for a fixed source
snapshot. [PAM instructions]({SUITE}/blob/{tag}/docs/pam-setup.md) and
[security model]({SUITE}/blob/{tag}/docs/security-model.md) describe touch-only
behavior, password fallback and limitations.

## Update and remove

While unlocked:

```sh
omarchy plugin update yubikey.{role}
```

To remove it:

```sh
omarchy plugin disable yubikey.{role}
omarchy plugin remove yubikey.{role}
```

On the supported host, disabling the clone restores the stock service. If you
previously used another custom clone, re-enable it yourself. Removal does not
change PAM or delete enrollment data. Follow the suite's rollback instructions
if you also want to undo that setup.

## Source and license

This is a distribution repository. Its maintained source is
[`plugins/yubikey.{role}`]({SUITE}/tree/{tag}/plugins/yubikey.{role}) in the suite.
`SOURCE.json` records the source ref and hashes of the exported files. Report
bugs and send changes to [the suite]({SUITE}/issues).

MIT; QML derives from the Omarchy shell. See `THIRD_PARTY_NOTICES.md`.
Independent community software, unaffiliated with Yubico, GNOME or Omarchy.
'''
    (destination / 'README.md').write_text(readme)
    # The source security policy links to the suite's security-model document.
    policy = (destination / 'SECURITY.md').read_text().replace('(docs/security-model.md)', f'({SUITE}/blob/{tag}/docs/security-model.md)')
    (destination / 'SECURITY.md').write_text(policy)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    for role in FILES:
        print(export(role, args.output.resolve()))


if __name__ == '__main__':
    main()
