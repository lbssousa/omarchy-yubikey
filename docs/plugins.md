# Shell plugins

The root [control center](control-center.md), `yubikey.setup`, provides setup,
management and a bar entry. It does not replace an authentication service.

The repository also ships two independent authentication plugins:

| ID | Replaces | Files |
| --- | --- | --- |
| `yubikey.polkit` | `omarchy.polkit` | `PolkitAgent.qml`, `PolkitModel.js` |
| `yubikey.lock` | `omarchy.lock` | `Service.qml`, `LockView.qml`, `LockActions.js` |

They import shared Omarchy QML modules. They are not standalone Quickshell
applications. The lock follows the current theme and background; no personal
wallpaper or theme files are bundled. Each plugin also includes
`Translations.qml`, `Locale.js` and its own `i18n/` catalogs. These follow the
account's Omarchy language live and support right-to-left layouts; see
[Languages](languages.md).

## Compatibility

The source was extracted from the Omarchy 4.0.6 plugin host. It needs
`qs.Commons`, `qs.Ui`, Quickshell's PAM/Polkit services and the host's
`omarchy.clonedFrom` handling for authentication services. Installing the
plugins grants them access to authentication input; review their source.

The lock calls the shell's existing wake, display-blanking and stranded-lock
helpers. Fingerprint is optional and detected separately. An incompatible shell
can reject or fail to load these plugins; use the stock services in that case.

## Power actions on the lock screen

The lock shows **Suspend** (F1), **Reboot** (F3) and **Shutdown** (F4) at the
bottom of the screen, the same keys as the SDDM greeter, so the machine can be
suspended or turned off without unlocking it, as from the login screen.

- Each action appears only when logind answers `yes` to `CanSuspend`,
  `CanReboot` or `CanPowerOff`: a `challenge` would need a polkit password in a
  prompt the lock covers. Suspend also follows Omarchy's `suspend-off` toggle
  and `omarchy-sleep-disabled`, like the system menu.
- Reboot and Shutdown ask first: Enter or a click confirms; Esc, typing or
  10 seconds cancel. Suspend runs at once.
- A key or click that wakes a blanked screen only wakes it.
- Actions run only the fixed `systemctl suspend`, `reboot` or `poweroff`, and
  clear anything typed in the field first. They don't unlock the session.

Anyone at the keyboard can reboot or shut down from here, as from the greeter;
other users' sessions close with it. logind refuses (and the lock hides the
action) while other users are logged in, unless polkit allows it without a
password.

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
nested includes or prove a key is connected. It shows the actual PAM prompt for
PIN or password responses. It does not collect secrets while PAM waits for touch.
With explicit fallback configured, key failure is followed by a **Use password**
button, not an automatically enabled account-password field. Escape cancels.

The lock checks `/etc/pam.d/omarchy-lock-fido2` and your user entry in
`/etc/fido2/fido2`. When configured, key authentication is selected initially.
**Use password**, **Use key / Retry key** and optional **Fingerprint** select one
conversation at a time and clear pending input. An absent key, PIN error or timeout
does not select password or automatically retry PINs. Insert a key and choose
**Retry key**; alternatively choose **Use password** immediately. PIN responses
go only to the key PAM context. Method buttons support Tab/Enter; when waiting
without an input prompt, P/K/F select password/key/fingerprint respectively.

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
