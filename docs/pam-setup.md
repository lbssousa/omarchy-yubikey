# PAM setup

These examples target Arch/Omarchy. Review your actual PAM stack; distribution
files are not interchangeable. For standard Arch stacks, `./install.sh` provides [guided setup](install.md)
with a review step, backups and rollback. This page covers manual configuration.

The configuration follows [Yubico's pam-u2f documentation](https://developers.yubico.com/pam-u2f/).
`sudo` authorization rules still apply: this changes authentication, not which
commands your account is allowed to run. It does not install a `NOPASSWD` rule.

## 1. Prepare a recovery path

Install `pam-u2f` and keep a separate root shell open during setup:

```sh
sudo pacman -S --needed pam-u2f
sudo -s
```

In that root shell, create a backup directory and copy the existing files there.
Keep the printed directory path for rollback. For Polkit, an existing default
may be in `/usr/lib/pam.d/polkit-1` instead of `/etc/pam.d`.

```sh
pam_backup_dir=$(mktemp -d /root/pam-yubikey-backup.XXXXXX)
cp -a /etc/pam.d/sudo "$pam_backup_dir/sudo"
if test -f /etc/pam.d/polkit-1; then
  cp -a /etc/pam.d/polkit-1 "$pam_backup_dir/polkit-1"
else
  cp -a /usr/lib/pam.d/polkit-1 "$pam_backup_dir/polkit-1"
fi
printf 'PAM backup: %s\n' "$pam_backup_dir"
```

Also back up an existing `/etc/fido2/fido2` and
`/etc/pam.d/omarchy-lock-fido2` before changing them. Do not overwrite an existing
mapping file with a new single-user enrollment.

## 2. Enroll your own key

In your **normal user terminal**, generate a mapping using a fixed origin.
It must match every PAM line below; the fixed value avoids binding to a hostname.
Unplug other keys for this first enrollment, then touch the intended key.

```sh
umask 077
mkdir -p "$HOME/.config/Yubico"
pamu2fcfg -o pam://omarchy -i pam://omarchy > "$HOME/.config/Yubico/omarchy-enrollment"
```

To add a backup key for the same user, unplug the first key, plug in the backup
and append with `-n` before installing the mapping:

```sh
pamu2fcfg -n -o pam://omarchy -i pam://omarchy >> "$HOME/.config/Yubico/omarchy-enrollment"
```

Keep the mapping for each user on **one logical line**, with the username only
once. `pamu2fcfg` emits entries suitable for appending; do not insert a newline
between keys. Check the file locally, without pasting it into an issue.

For a new installation only, copy the mapping into the root-owned central file:

```sh
sudo install -d -m 0755 /etc/fido2
# Stop here if this exists; merge locally instead of replacing other enrollments.
test ! -e /etc/fido2/fido2 && \
  sudo install -o root -g root -m 0644 "$HOME/.config/Yubico/omarchy-enrollment" /etc/fido2/fido2
```

The mapping contains public credential information, not a private key. It is
readable because the unprivileged lock plugin checks enrollment. It must remain
writable only by root. Do not commit it or your temporary enrollment file.
After successful setup, remove that temporary copy locally.

## 3. Enable sudo and Polkit

Use `sudoedit /etc/pam.d/sudo`. Insert the active line from
[`pam/passwordless-auth.conf`](../pam/passwordless-auth.conf) **before** the
existing `auth` rules:

```pam
auth sufficient pam_u2f.so cue origin=pam://omarchy appid=pam://omarchy authfile=/etc/fido2/fido2
```

Keep all existing authentication, account and session rules. `sufficient`
allows successful key authentication to skip the later password rules. Failure
continues through your existing stack. The provided line does not request a PIN.

Apply the same line to `/etc/pam.d/polkit-1`. If only a default under
`/usr/lib/pam.d` exists, copy that default to `/etc/pam.d` first, then edit the
copy. Preserve its remaining rules too. Existing required modules or custom
control flow can change the result; inspect those before adding this line.

From a fresh user terminal:

```sh
sudo -k
sudo true
```

Touch the key and verify success. Then unplug it, invalidate the timestamp
again and verify the normal password still works. Trigger a known benign
Polkit action and test both paths there too. Password entry can wait for a key
timeout when a registered key is present but untouched.

For PIN or biometric verification, consult Yubico's upstream options and enroll
accordingly. The shell's simple touch prompt is not qualified for those modes.

## 4. Enable screen unlock

The key-only lock service must use **required**, not `sufficient`, because it
has no password stack of its own. Password and fingerprint run as separate PAM
contexts in the QML plugin.

After backing up any existing service, review and install the supplied template
from the repository root:

```sh
sudo install -o root -g root -m 0644 pam/omarchy-lock-fido2 /etc/pam.d/omarchy-lock-fido2
```

The shell also needs its existing `/etc/pam.d/omarchy-lock-password`. This repo
does not replace that distribution-managed service or alter your login manager.
Before locking, verify password unlock works with the stock lock plugin. Then
follow [plugin activation and testing](plugins.md).

## Rollback

Use the root shell you kept open. Restore the sudo and Polkit backups from the
saved directory. If Polkit originally had no `/etc` override, remove only the
override you created to return to the packaged `/usr/lib` default. Restore an
old key-only service or remove the new `/etc/pam.d/omarchy-lock-fido2` if none
existed. Restore the previous mapping if changed.

Disable the two custom plugins as described in [plugins](plugins.md) before
removing their directories. Check password sudo and screen unlock again before
closing the recovery shell. If access is lost, use your distribution's rescue
or live-media procedure to restore the saved PAM files.
