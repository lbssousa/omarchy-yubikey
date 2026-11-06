# Resident SSH keys

FIDO2 security keys can store resident (discoverable) SSH keys, created with
`ssh-keygen -t ed25519-sk -O resident`. The *Security keys* page of the control
center copies them into `~/.ssh`, for example on a new computer, as the desktop
user and without privileges. Like every other action, each one opens a terminal
first; the FIDO2 PIN stays in that terminal.

The **Resident SSH keys** card lists the resident key files in `~/.ssh` by
number only, each described by its type (Ed25519-SK or ECDSA-SK), whether a
passphrase protects the copied file and whether a git-host drop-in uses it.
The window never receives file names, applications or user IDs.

| Action | What happens in the terminal |
| --- | --- |
| **Import SSH keys** | Runs `ssh-keygen -K` in a private temporary directory, where ssh-keygen asks for the PIN, a touch and an optional passphrase for each copied file. Every `id_*_sk_rk*` pair is then moved into `~/.ssh` (0600 for the private file, 0644 for the `.pub`), **never over an existing file**: a pair whose name is already taken is reported and left out. |
| **Remove** (on a key's row) | Names the file behind that number, then deletes it and its `.pub` after a confirmation. The number follows the window's last refresh, so check the file name before confirming if `~/.ssh` changed meanwhile; a number past the end of the list stops without removing anything. The credential stays on the security key and can be imported again. |

## Git hosts

A resident key made for a git host names it in its application
(`ssh-keygen -t ed25519-sk -O resident -O application=ssh:github.com`), which
`ssh-keygen -K` keeps as the comment of the `.pub` file. For each such host the
import offers to create a drop-in `~/.ssh/config.d/<host>.conf`:

```
# Created by omarchy-yubikey for resident SSH keys.
Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com
    IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com_work
    IdentitiesOnly yes
    IdentityAgent none
    ControlMaster auto
    ControlPath ~/.ssh/control/%C
    ControlPersist 15m
```

- After `ssh:`, the application may be `host`, `login@host` or
  `//login@host:port`; the login defaults to `git`. The key's user ID (`-O user=`)
  is ignored: it is usually an account name or random, not an SSH login.
- A host counts as a git host if it is a known one (GitHub, GitLab, Bitbucket,
  Codeberg, SourceHut, Gitea, Azure DevOps) or if any of its names before the
  top-level domain contains `git`, as in `git.example.com` or `gitlab.example.org`.
- All keys for the same host go into one drop-in. ssh offers their public keys in
  that order, and only the one the server accepts asks for a touch.
- `IdentitiesOnly` and `IdentityAgent none` make ssh use these key files directly,
  without the SSH agent or other keys.
- The terminal asks how many minutes the first connection stays open for reuse
  (default 15, at most 1440; 0 leaves the `Control*` lines out). While it is open,
  new connections to that host reuse it **without a PIN or touch**.
- An existing drop-in for the same host is never replaced.
- If `~/.ssh/config` does not include `~/.ssh/config.d`, the import offers to add
  `Include config.d/*.conf` at its top, where it applies to every host, and
  keeps the file's other contents and permissions. It does not edit a symbolic link.

**Remove** also takes the key's line out of the drop-in created for it,
and deletes the drop-in once no key is left. Drop-ins written by hand are left alone.

Copied files are key handles, not the private key itself: they only work with
the security key connected. A passphrase still protects them from use on
another machine together with a stolen key.
