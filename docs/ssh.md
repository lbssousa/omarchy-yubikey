# Resident SSH keys

The **Resident SSH keys** card copies resident security-key handles into
`~/.ssh` as the desktop user, for example on a new computer. Create such keys
with `ssh-keygen -t ed25519-sk -O resident`. Each action opens an interactive
terminal; the PIN and passphrases go to ssh-keygen itself.

Each row shows the public application, key type, selectable SHA256 public
fingerprint, passphrase flag and whether the managed configuration lists it.
Applications are read from the public-key blob, not its editable comment.
Each row also shows the key's FIDO2 user ID, which tells apart keys made for the
same application. It is read from the handle's filename, where `ssh-keygen -K`
puts it (binary user IDs as hexadecimal, shortened in the window). Filenames and
credential handles are not sent to the window.

| Action | What happens |
| --- | --- |
| **Create SSH key** | Asks for each option in the terminal (see [Create a resident key](#create-a-resident-key)), shows the `ssh-keygen` command and asks before running it. The key is generated on the security key; its handle file is installed like an imported one. |
| **Delete from security key** (in a key's box, next to **Remove copy**, in the urgent colour) | **Permanently** deletes that key from the security key itself, then removes its copy (see [Delete a resident key](#delete-a-resident-key-from-the-security-key)). It cannot be recovered or imported again. |
| **Import SSH keys** | Runs `ssh-keygen -K` in a private temporary directory, then installs complete pairs at 0600/0644. Existing files, including either half of a pair, are never overwritten. An incomplete/failed download installs nothing. Failed pair copies roll back files created for that pair. |
| **Remove copy** (in a key's box) | Passes a stable reference to the exact filename and public identity, rather than a row number. The terminal identifies the public fingerprint and filename before confirmation. A disappeared/replaced public key cannot redirect removal to another row, and both file contents are rechecked after confirmation. Only the copy in `~/.ssh` is removed; the key stays on the security key and can be imported again. |

SSH management directories must be owned by the account and private (0700).
Symlinks, nonregular files, oversized input and concurrent tool operations are
rejected. Existing directory permissions are not silently relaxed or changed.

## Create a resident key

**Create SSH key** opens a terminal wizard. Press Enter to keep a suggestion:

| Option | Suggestion | `ssh-keygen` |
| --- | --- | --- |
| Algorithm | `ed25519-sk`; `ecdsa-sk` for keys without Ed25519 (YubiKey firmware before 5.2.3) | `-t` |
| Application | empty (`ssh:`); a name or host such as `github.com` | `-O application=ssh:<value>` |
| User ID | a random 16-character hexadecimal value; type your own, or `-` for none. Without a user ID, `ssh-keygen` sends 32 zero bytes, so every such key for the same application replaces the previous one | `-O user=<value>` |
| PIN for every use | yes | `-O verify-required` |
| Touch for every use | yes; no adds `-O no-touch-required`, which `sshd` refuses unless `authorized_keys` allows it | `-O no-touch-required` |
| Comment | `<user>@<hostname>` | `-C` |

The application and user ID accept letters, digits and `. _ - @` (the application
also `:`), without slashes or `..`, so the handle gets the same filename that
**Import SSH keys** would give it (`id_<type>_rk[_<application>][_<user ID>]`).
`ssh-keygen` itself asks for the FIDO2 PIN, a touch and an optional passphrase for
the handle file.

A new key with the same application and user ID as an existing resident key
**replaces it on the security key**; `ssh-keygen` asks before overwriting it. If
`~/.ssh` already has a file with the new key's name, nothing is copied and the key
stays only on the security key, ready to import later. After creating the key, the
wizard prints the public key and fingerprint to add to the server or Git host, and
offers the Git-host configuration below when the application names one.
Removing the copy keeps the credential on the security key;
the row's **Delete from security key** removes it there, permanently.

## Delete a resident key from the security key

> **This cannot be undone.** Deleting a resident key removes it from the security
> key itself. Unlike removing only the copy in `~/.ssh`, the key cannot be
> recovered or imported again, and every server or Git host that trusts it needs a
> new key.

Each key's row has its own **Delete from security key** button, next to **Remove
copy**. Its confirmation dialog carries this warning, and the terminal:

1. prints the warning again, and names the selected copy's fingerprint and application;
2. runs `fido2-token -L -k <application>` and picks the key whose user ID matches the
   copy's filename (including user IDs that `ssh-keygen -K` wrote as hexadecimal). If
   no single key matches, it lists the application's keys by user ID and type;
3. requires typing `DELETE <application>`;
4. runs `fido2-token -D -i <credential id>`, then removes the copy, which no longer
   works, and its Git-host entry.

`fido2-token` asks for the FIDO2 PIN in steps 2 and 4. Only one security key may be
connected. A key that is only on the security key, without a copy in `~/.ssh`, is
imported first and then deleted from its row.

## Git hosts

For an application such as `ssh:github.com`, import offers to configure the
matching Git host. Applications may name a host, a login and host, or a login,
host and port. Only validated known forges or names with `git` in a label before
the top-level domain are offered; the default SSH login is `git`.

The tool owns one file, `~/.ssh/omarchy-yubikey/config`, and one canonical
global `Include omarchy-yubikey/config` at the beginning of `~/.ssh/config`.
It does not adopt or edit general `config.d` files. An unrelated or conditional
Include does not suppress the global managed Include. The main file's remaining
contents and mode are preserved; a symbolic-link main config is refused.

All selected keys for the same login/host/port share a Host entry. Reimporting
a removed key offers to restore its IdentityFile line; adding another key offers
to extend the same entry. Conflicting logins or ports are reported.

Before applying a configuration update, the terminal shows its diff and uses
`ssh -G` to compare effective settings for each managed host, including existing
Host/Match rules. Invalid or conflicting configurations are not installed.
Existing explicit IdentityFile directives can add other keys; their effective
list is included in the preview. Disabling the agent does not remove those
directives.

The managed file carries its source model in a comment and is replaced
atomically. Hand edits to its body are detected; applying the proposed
replacement requires typing **REPLACE**, not just answering yes. The model and
configuration are in the same file, avoiding a split manifest/config update.
If its header is missing or invalid, move the file aside and review it manually.

## Connection reuse

The default is **0 minutes**, with explicit `ControlMaster no`,
`ControlPath none` and `ControlPersist no`. This also disables inherited
multiplexing for these hosts. Every new connection performs authentication;
the card's own policies determine whether a PIN and touch are required.

A positive duration, up to 1440 minutes, is an explicit choice. For that
duration, additional connections can reuse the authenticated session without
another PIN or touch. Removing a copied key does not terminate existing SSH
connections or revoke the credential on the security key.

Removal proposes an update to the managed configuration before deleting the
key pair. Cancelling that update preserves both files. Empty Host entries are
removed; an empty managed file and its Include are harmless and retained.
Existing legacy `config.d/<host>.conf` files from preview versions are not
automatically migrated: inspect and remove those manually before enabling the
new configuration, using the effective-settings preview as a check.

Copied private files contain hardware-bound handles, not the private signing
key. Their passphrases still matter if both a handle and the physical key are
stolen. Software tests use synthetic public blobs and real `ssh -G`; actual
authentication and connection reuse require hardware/server testing.
