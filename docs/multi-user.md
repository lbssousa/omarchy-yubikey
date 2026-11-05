# Multiple Linux accounts

Enrollment, the Keyring helper and desktop plugins support separate local Linux
accounts on the same machine. Run setup as each account's normal desktop user.
Do not run another user's desktop setup through `sudo` or share home directories.

| Data or policy | Scope |
| --- | --- |
| Security-key mapping | Shared root-controlled file, with separate entries keyed by account name |
| PAM authentication mode and password-fallback policy | System-wide, per PAM service |
| Keyring password store and helper lock | Per user, under that account's config and runtime directories |
| Plugin installation, enabled clones and user backups | Per user |
| Display language | Per user |
| Signed-transfer trust and accepted revisions | Bound to each account, maintained by root |
| LUKS disk-unlock tokens | Per volume; independent of desktop accounts |

## Enrolling another account

Log in as the second user and run `./install.sh`. The installer merges that
account's keys into the central mapping without replacing other accounts.
The same physical key can hold separate enrollments for different accounts;
credentials must be enrolled for each account. Knowing one account's key mapping
does not grant access to another account.

The lock authenticates the account that owns the session. Polkit decides which
identity is allowed to authorize a particular action; this project does not
turn a user's enrolled key into authorization for arbitrary administrator
accounts. GNOME Keyring access stays on the user's session bus.

PAM settings are shared. Adding a second account with the existing policy only
updates that account's mapping. If setup would change shared PAM rules while
other accounts are enrolled, the planner refuses by default. The installer
explains this and offers a separate confirmation, defaulting to no. For a
reviewed administrator change, the setup CLI has
`--allow-shared-policy-change`; this permission does not bypass account binding
or key verification. Coordinate the change with all affected users.

## Accounts without sudo

By default, adding or removing a key runs `configure-pam.py` through `sudo`, so
only administrators can manage their keys. Setup offers to install a small
helper for everyone else (`./install.sh --key-helper` installs it later,
`./install.sh --remove-key-helper` removes it):

- a root-owned copy of `scripts/key-mapping-helper`, `configure-pam.py` and
  `i18n.py` in `/usr/local/libexec/omarchy-yubikey`, so pkexec never runs
  code from a user-writable checkout;
- the polkit action `org.omarchy-yubikey.key-mapping`, which asks the account
  for **its own** password (`auth_self`), not an administrator's.

The helper takes the account from `PKEXEC_UID` only, never from its arguments
or input, and changes only that account's line of `/etc/fido2/fido2`, through
the same transaction lock, backups and rollback as setup. It never changes PAM
policy, and it keeps the last key. Registering a key this way grants no
administrator rights: the key authenticates the same account, for whatever
that account could already do. Rerun `--key-helper` after updating the
checkout to refresh the installed copy.

## Rollback and concurrent changes

Setup, imports and rollback use one root-controlled transaction lock. Backups
record fingerprints of the files written by their transaction. Before a manual
rollback, every target is checked; a later enrollment or configuration change
causes rollback to stop before modifying any file. This prevents an older backup
from silently removing another account's newer enrollment.

Legacy backups without those fingerprints require manual review and restoration.
A current backup with unchanged targets can still be restored normally. Signed
transfer revision watermarks remain preserved during manual rollback, so an old
signed export cannot be replayed afterward.

These are local-account boundaries, not directory-service provisioning or a
user-switcher feature. Every account still needs its own desktop plugin setup,
key enrollment and recovery method. Shared machine policies should be managed by
an administrator. Real simultaneous desktop sessions require separate hardware
qualification; automated tests cover account isolation and transaction behavior.
