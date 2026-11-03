# Shell plugins

The repository ships two independent plugins:

| ID | Replaces | Files |
| --- | --- | --- |
| `yubikey.polkit` | `omarchy.polkit` | `PolkitAgent.qml`, `PolkitModel.js` |
| `yubikey.lock` | `omarchy.lock` | `Service.qml`, `LockView.qml` |

They import shared Omarchy QML modules. They are not standalone Quickshell
applications. The lock follows the current theme and background; no personal
wallpaper or theme files are bundled.

## Compatibility

The source was extracted from the Omarchy 4.0.6 plugin host. It needs
`qs.Commons`, `qs.Ui`, Quickshell's PAM/Polkit services and the host's
`omarchy.clonedFrom` handling for authentication services. Installing the
plugins grants them access to authentication input; review their source.

The lock calls the shell's existing wake, display-blanking and stranded-lock
helpers. Fingerprint is optional and detected separately. An incompatible shell
can reject or fail to load these plugins; use the stock services in that case.

## Guided setup

Run `./install.sh` and select desktop integration. The wizard prepares PAM,
backs up the shell selection and existing plugin copies, and switches the
active authentication clones. See [installation](install.md). The steps below
are the manual alternative.

## Copy and validate

Run from the repository root:

```sh
./scripts/install-plugins.sh
omarchy-shell shell rescanPlugins
omarchy plugin validate "$HOME/.config/omarchy/plugins/yubikey.polkit"
omarchy plugin validate "$HOME/.config/omarchy/plugins/yubikey.lock"
```

The script copies only the two plugin directories, refuses existing target
directories by default and does not enable anything or modify PAM. Use
`--update` to back up and replace existing copies while unlocked. It honors
`XDG_CONFIG_HOME`; adjust the validation paths above if you use it.

## Activate while unlocked

Back up your shell configuration first. Disable any other custom Polkit or lock
replacement you already use. Keep a recovery terminal and the stock plugins
available. Enable the replacements through the host:

```sh
omarchy plugin enable yubikey.polkit
omarchy plugin enable yubikey.lock
```

The `clonedFrom` metadata lets the host replace the corresponding stock service;
there must be only one active Polkit agent and one session-lock service. Do not
activate or remove a lock plugin while the session is locked.

Complete [PAM setup](pam-setup.md) first. The Polkit prompt infers key availability
from a direct `pam_u2f.so` line in `/etc/pam.d/polkit-1`; it does not resolve
nested includes or prove a key is connected. It switches to password input when
PAM requests a response. Typing ahead does not cancel a pending key operation.

The lock checks `/etc/pam.d/omarchy-lock-fido2` and your user entry in
`/etc/fido2/fido2`, then runs that key flow alongside the password flow. An absent
key does not block password entry. Background retries allow a key to be inserted
while the screen is locked.

## Verify before relying on it

Test Polkit success, cancellation, wrong passwords and the absent-key fallback.
For the lock, first use its preview if your host exposes it:

```sh
omarchy-shell lock preview
```

A preview is visual only. With a recovery path ready, test a real session lock
with the key, with the key unplugged and with a wrong password. Then check
suspend/resume and each attached display. A successful build or preview does
not establish that a real session can be unlocked.

## Update or remove

While unlocked, disable the plugins before replacing or removing their files:

```sh
omarchy plugin disable yubikey.lock
omarchy plugin disable yubikey.polkit
```

On the compatible host, disabling a clone restores its stock source. Verify
those services are active again. Then remove only these two plugin directories
or copy the reviewed updated versions into them and re-enable. Restore your
shell configuration backup if another custom replacement was previously active.
PAM configuration is separate and remains until you roll it back explicitly.
