# GNOME Keyring helper

This user-session tool is independent of passwordless sudo. It uses a
nonresident FIDO2 credential with `hmac-secret`, HKDF-SHA256 and
ChaCha20-Poly1305 to encrypt an existing secret locally. A key touch decrypts it
for use in the current session. See the [security model](security-model.md).

## Guided setup

Run `./install.sh` and select GNOME Keyring. The wizard builds the helper,
backs up existing files, guides enrollment and offers startup integration.
See [installation](install.md). The steps below are the manual alternative.

## Build and install

```sh
sudo pacman -S --needed base-devel rust clang pkgconf libfido2 openssl systemd-libs
cargo build --release --locked
install -d "$HOME/.local/bin"
install -m 0755 target/release/keyring-unlock "$HOME/.local/bin/"
```

The commands below assume `~/.local/bin` is on `PATH`. There are no prebuilt
binaries. CLI messages are currently German. Plug in only the key you intend to
enroll; enrollment considers all connected supported keys. Keep your original
password and recovery method.

The exported project uses a new, project-owned FIDO relying-party identifier.
Encrypted stores from the earlier local prototype are not compatible: back them
up outside the repository and enroll afresh. Do not overwrite a working helper
until you have planned that migration.

## GNOME Keyring

GNOME Keyring must be running on your session bus with a default collection.
Enrollment asks twice for that collection's existing password, briefly locks it
and unlocks it to validate the password. It then creates credentials and encrypts
the password for the connected keys. Enrollment can request a FIDO2 PIN if the
key requires one for creating credentials; normal unlock requests touch only.

```sh
keyring-unlock enroll --label "Primary key"
keyring-unlock check
keyring-unlock unlock
keyring-unlock status
```

`check` decrypts without unlocking a collection or printing the password.
`unlock` also attempts other locked collections that share the same password;
collections with different passwords stay locked. GNOME's internal
`UnlockWithMasterPassword` D-Bus method is used and may change between versions.

To add a backup key, connect it and use `enroll --add --label "Backup key"`.
Without `--add`, enrollment replaces the helper's current entries. After a
keyring password change, enroll again with the new password.

For one unlock attempt at each graphical login:

```sh
install -d "$HOME/.config/systemd/user"
install -m 0644 systemd/keyring-unlock.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable keyring-unlock.service
```

This oneshot unit does not keep retrying if the key was absent at startup. Run
`keyring-unlock unlock` later when needed. It does not enable autologin or disable
the keyring's normal password prompt.

The legacy `merge` subcommand copies items into the default collection and
**deletes source collections**. It is not needed for setup. It is inherited,
unqualified for general use, and should only be considered with a verified
keyring backup and an explicit understanding of its duplicate-item handling.

## Data, logs and removal

| Tool | Default local store | Override |
| --- | --- | --- |
| Keyring | `~/.config/keyring-unlock/password.json` | `KEYRING_UNLOCK_STORE` |

The store honors `XDG_CONFIG_HOME`. Its contents include credential handles,
labels, timestamps, salts, nonces and encrypted secrets. Keep it private and
outside version control. Losing the store requires enrollment again; losing the
key requires a backup key or the original password.

```sh
journalctl --user -u keyring-unlock.service
systemctl --user disable --now keyring-unlock.service
```

Remove the installed unit and binary if no longer needed, then run
`systemctl --user daemon-reload`. Delete encrypted stores only when you no longer
need them and have verified ordinary password access. Removing this
helper does not change PAM or remove web passkeys from your security key.
