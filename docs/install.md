# Guided installation

The guided installer supports **Arch Linux and compatible Omarchy 4 shells**.
You need an interactive terminal, a security key and working sudo access.
Desktop integration requires the existing password lock to work first.

## Start with one command

Clone the release and start setup:

```sh
git clone --depth 1 --branch v0.3.0 https://github.com/marselnenaj/omarchy-yubikey.git && ./omarchy-yubikey/install.sh
```

Already cloned? Run `./install.sh` from that checkout. To inspect prerequisites
without changing anything, run `./install.sh --check`. You can review the
[installer source](../install.sh) before running it.

## What setup asks

Disk encryption is separate: `./install.sh --luks --device /dev/your-luks-partition`
starts opt-in LUKS2 enrollment. It requests **PIN plus touch**, makes private
header backups, offers backup/recovery keys and leaves existing slots intact.
It does not edit boot files. Read [LUKS boot integration and rollback](luks.md)
before using it; PAM rollback below does not undo LUKS enrollment or boot changes.

1. **Choose features.** sudo and desktop integration are offered separately.
   The optional GNOME Keyring helper is off by default.
2. **Prepare recovery.** Keep a separate `sudo -s` shell open while setting up
   authentication. The wizard explains this before making changes.
3. **Choose key policy and enroll.** PIN plus touch and explicit password fallback
   default to yes. Set a FIDO2 PIN on the key beforehand. Touch-only and automatic
   fallback require choosing no at their respective questions. Plug in one key;
   enter its PIN when asked and touch it when it blinks. You can add a
   backup key too. Existing users and keys in the central mapping are preserved.
4. **Review the plan.** The installer lists the files it will change and asks
   before applying them. Original PAM files and mappings are backed up first.
5. **Test authentication.** If sudo was selected, the wizard walks you through
   password authentication with the key unplugged, then key authentication.
6. **Enable the desktop.** The selected lock and Polkit plugins replace existing
   authentication clones after a shell-config backup. Test an actual lock and a
   benign privileged action before closing the recovery shell.

Explicit fallback builds a small Linux-PAM conversation gate from source, then
backs it up and installs it alongside the reviewed PAM changes. After key failure
or timeout, sudo asks you to type the literal word `password` before showing the
account-password prompt. Polkit shows a **Use password** button. The lock has
separate method buttons; its PIN field belongs only to the key conversation.
Neither choosing fallback nor confirming it authenticates you by itself.

The installer supports standard Arch
`auth include system-auth` stacks; it stops on custom stacks for manual review
instead of rewriting their policy. See the [security model](security-model.md).

If you select Keyring, setup also builds the Rust helper, asks for your existing
keyring password, enrolls the key and checks decryption. It offers startup
integration separately. Existing helper binaries and encrypted stores are
backed up; an enrollment failure restores those copies. Your ordinary keyring
password remains usable. See [the Keyring guide](keyring.md).

Git enrollment transfer is separately opt-in through `./install.sh --sync`.
It does not run during normal setup, create a repository, upload mappings or
automatically change PAM. See [signed enrollment transfer](enrollment-sync.md).

Setup follows the account's [display language](languages.md). On a shared
machine, review the [multiple-account guide](multi-user.md) before changing
PAM policy; authentication mode and fallback rules affect every account.

## Backups and rollback

The installer prints the system backup ID. From the checkout, restore it with:

```sh
./install.sh --rollback BACKUP_ID
```

If sudo no longer works, use the recovery root shell you kept open:

```sh
python3 scripts/configure-pam.py --rollback /var/lib/omarchy-yubikey/backups/BACKUP_ID
```

PAM rollback restores the selected files and removes overrides created during
that setup only when the targets still match that transaction. Later enrollment
or configuration changes stop rollback before anything is written. Legacy
backups without conflict fingerprints require manual review and restoration.
See [multiple accounts](multi-user.md) for shared-policy and rollback behavior.
It does not change the currently selected desktop plugins or Keyring helper.

While the desktop is unlocked, disable the replacements to return to the stock
services:

```sh
omarchy plugin disable yubikey.lock
omarchy plugin disable yubikey.polkit
```

User backups live under `$XDG_STATE_HOME/omarchy-yubikey/backups` (normally
`~/.local/state/omarchy-yubikey/backups`). Setup prints the exact directory.
A `shell.json` backup preserves the previous plugin selection; restore it while
unlocked if you previously used other authentication clones. Plugin updates also
keep copies of the previous plugin directories there. Keyring backups can
contain an encrypted password store: keep the directory private and outside Git.

For manual installation or a custom PAM stack, use [PAM setup](pam-setup.md),
[shell plugins](plugins.md) and [Keyring](keyring.md).

## Current validation

PAM planning, preservation of other enrollments, rollback, file permissions and
interrupted writes are covered by isolated tests. A fresh end-to-end hardware
enrollment test of this installer is still pending. Keep a recovery path
available while setting up and testing your own system.
