# Omarchy YubiKey control center

The root of this repository is the `yubikey.setup` plugin. It adds a theme-aware
setup window and a key button in the Omarchy bar. It does not replace an
authentication service. The included lock and Polkit plugins remain separate
components, activated only through desktop setup or their own installation.

## Install and open

On a compatible Omarchy 4 desktop with Python 3:

```sh
omarchy plugin add https://github.com/marselnenaj/omarchy-yubikey.git
omarchy plugin enable yubikey.setup
omarchy-shell shell summon yubikey.setup '{}'
```

The host can offer to enable the plugin during installation. Once enabled, use
its key button in the bar. Adding/enabling the control center reads status; it
does not enroll keys, install packages, edit PAM or enable login helpers.
Review the source and [dependencies](../README.md#requirements-and-compatibility).
The interface is available in English and German, follows the account's Omarchy
language live, and falls back to English for other languages. Existing lock,
Polkit and helper catalogs still support all 50 Omarchy languages.

## What the window does

| Page | Status and actions |
| --- | --- |
| Overview | Current account's PAM enrollment count, connected FIDO2-device count, sudo policy, desktop plugin and Keyring status; guided setup |
| Security keys | Add a PIN-protected PAM backup key or remove one registration; import, trust or remove the OpenPGP key of a connected card ([OpenPGP card](openpgp.md)); create a resident SSH key, copy resident SSH keys or remove a copy ([SSH](ssh.md)); guides to separate Keyring/LUKS enrollments and signed transfer |
| Desktop | Set up or test sudo; configure the included lock/Polkit plugins; switch back to stock plugins while unlocked |
| Keyring | Install the optional Rust helper; preserve existing enrollments; add a backup key; test decryption; unlock; enable/disable an installed login service |
| Disk & recovery | Check/enroll an explicitly entered existing LUKS2 device; open the boot guide; list system PAM backup IDs and restore one selected backup |

Counts describe configuration, not successful authentication. USB discovery
counts FIDO2 devices, not necessarily enrolled YubiKeys. No device serials,
credential handles, encrypted passwords or collection labels are shown.
The key-management cards may show bounded public fingerprints and SSH
applications. OpenPGP name/email is optional and hidden initially. Fingerprints
can be selected and copied; raw command output and private handles never enter
the model. SSH removal selects a stable key reference and checks the files
again after confirmation, so changing row positions cannot select another key.
The window neither guesses a disk nor changes boot configuration.

Every action first offers **Cancel** or **Open terminal**, defaulting to Cancel.
The terminal identifies the operation and asks before starting it. Setup then
presents its own choices, preview and confirmations. PINs, account passwords,
keyring passwords and disk recovery keys stay in those interactive terminal
programs; their output is not captured into the window or operation records.
Keep a separate recovery root shell open when changing PAM. The original
password stack is preserved, but test actual authentication before relying on it.

Only one control-center operation can run per account. A private advisory lock
and a short-lived handoff ticket prevent accidental double launches. The window
refreshes local status while open and reports interrupted operations; completion
does not mean an untested key or boot setup has been qualified.
State files under `$XDG_STATE_HOME/omarchy-yubikey/control-center` contain only
an action name, phase, time and temporary handoff ticket, never authentication
responses, device paths or backup IDs. This is coordination, not a privilege
boundary against another process already running as the same account.

## Backup keys and removal

**Add key / backup key** merges a new PIN-protected credential into the current
account's mapping without changing shared PAM policy. It prints an opaque key
reference; save that reference privately to identify the registration later.
It is not the key's serial number. Account mappings for other users are preserved.

**Remove a registration** lists references in the terminal. Match the saved
reference, select it, review the preview and type the requested confirmation.
Do not guess which physical key an older registration belongs to. At least one
PAM registration must remain; duplicate or missing references are rejected.
The mapping change has a versioned backup and conflict-aware rollback.
Removal does not erase the physical key or revoke any Keyring, LUKS or website
credentials. Enroll and test a backup key separately for every feature used.

## Recovery and removal

**Show backups** prints IDs and affected paths in a sudo terminal, without
credential contents. Enter an ID in **Restore a PAM backup** to run the existing
conflict-aware rollback. Files changed since that transaction cause rollback
to stop before writing. This does not undo plugin selection, Keyring or LUKS.
See [installation recovery](install.md), [Keyring removal](keyring.md) and
[LUKS recovery](luks.md).

While unlocked, **Use standard plugins** disables only `yubikey.lock` and
`yubikey.polkit`; the supported host restores its stock services. PAM and enrolled
credentials remain. Other custom clones need separate manual review.

To remove only the control center, finish/close any setup terminal first:

```sh
omarchy plugin disable yubikey.setup
omarchy plugin remove yubikey.setup
```

This removes the window/bar entry. It does not delete system backups, remove
packages, undo PAM, erase keys, disable the separate authentication plugins or
remove the Keyring login service. Removing the control center during an active
operation is unsupported. Follow the respective component guide to undo it.

The full desktop wizard backs up and replaces existing copies of the two
`yubikey.*` authentication plugins. Avoid mixing separately Git-managed clones
with those copied installations. Keep the central setup plugin installed in its
own `yubikey.setup` directory; never copy the whole repository over a lock or
Polkit plugin directory.

## Validation

The model/backend tests use synthetic filesystem roots. Native Quickshell checks
render all five pages with synthetic data and exercise keyboard cancellation,
confirmation, validated device arguments, busy-state rejection and navigation.
To reproduce on Omarchy with QtTest installed:

```sh
python3 scripts/test-control-ui.py
python3 scripts/test-control-ui.py --width 640 --height 680 --language de
```

`preview.png` was captured from this fixture, not from a personal account.
These checks do not enroll real hardware, change the live PAM stack or qualify
boot recovery. The lock/Polkit components and Rust helper retain their existing
versions; the new control center is version 0.4.0. MIT; see [third-party
notices](../THIRD_PARTY_NOTICES.md) for Omarchy-derived components.
