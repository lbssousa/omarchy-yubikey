# Resident SSH keys

FIDO2 security keys can store resident (discoverable) SSH keys, created with
`ssh-keygen -t ed25519-sk -O resident`. The *Security keys* page of the control
center copies them into `~/.ssh`, for example on a new computer, as the desktop
user and without privileges. Like every other action, each one opens a terminal
first; the FIDO2 PIN stays in that terminal.

The **Resident SSH keys** card shows how many resident key files `~/.ssh`
holds. The window receives only that count, never file names, applications or
user names.

| Action | What happens in the terminal |
| --- | --- |
| **Import SSH keys** | Runs `ssh-keygen -K` in a private temporary directory, where ssh-keygen asks for the PIN, a touch and an optional passphrase for each copied file. Every `id_*_sk_rk*` pair is then moved into `~/.ssh` (0600 for the private file, 0644 for the `.pub`), **never over an existing file**: a pair whose name is already taken is reported and left out. |
| **Remove a copy** | Lists the resident key files in `~/.ssh`, then deletes the chosen file and its `.pub` after a confirmation. The credential stays on the security key and can be imported again. |

Copied files are key handles, not the private key itself: they only work with
the security key connected. A passphrase still protects them from use on
another machine together with a stolen key.
