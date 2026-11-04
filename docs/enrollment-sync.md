# Optional signed enrollment transfer through Git

This is opt-in transfer of **PAM enrollment mappings only**, using a separate
private Git repository as transport. Git fetch/commit/push run as your normal
user. A root import verifies a signed snapshot and asks for approval before
installing a root-owned copy. PAM never reads a Git checkout directly.

Mappings contain credential IDs and public keys, not the private key or PIN.
They still identify which credentials belong to an account. Signatures protect
integrity, not confidentiality: use a private repo, restrict access and review
its visibility yourself. The tool does not create a remote or upload anything.
Only modern nonresident pamu2fcfg entries with user presence are supported.
The optional Keyring store, passwords, PINs, disk headers and LUKS tokens are
outside this workflow and must not be committed.

## Trust and scope

Use one account and one authoritative exporting machine per sync repo. All target
machines must deliberately use the same relying-party ID, `pam://omarchy`, and
the same account name. The tool cannot infer the origin of an existing mapping;
only export credentials enrolled with this project's matching origin. No account
remapping is performed. Credentials shared across machines share their revocation
scope: prefer separate enrollments if you need independent per-machine revocation.

The signing key authorizes changes to your account's accepted keys. Protect it
with a passphrase, keep it outside the repo, and use a separate signing key rather
than your routine Git authentication key. OpenSSH hardware-backed signing keys
are also supported where your installed OpenSSH/key supports signing. Signing
and FIDO2 PAM authentication are separate roles.

Generate the signing key on your exporting machine (interactive passphrase):

```sh
ssh-keygen -t ed25519 -f "$HOME/.ssh/omarchy-enrollment-signing" -C "enrollment-sync"
ssh-keygen -lf "$HOME/.ssh/omarchy-enrollment-signing.pub"
```

On **each importing machine**, obtain that public key through a trusted channel
and compare its fingerprint outside the sync repo. Never bootstrap trust from a
key supplied by an untrusted export. After reviewing the public key locally,
create an allowed-signers file with your actual local account name:

```sh
printf 'omarchy-yubikey:%s namespaces="omarchy-yubikey-enrollment-v1" %s\n' \
  "$(id -un)" "$(cat /path/to/verified-signing-key.pub)" > allowed-signers
sudo install -d -o root -g root -m 0755 /etc/fido2
# If this already exists, review/merge with sudoedit instead of replacing it.
test ! -e /etc/fido2/sync_allowed_signers && \
  sudo install -o root -g root -m 0644 allowed-signers /etc/fido2/sync_allowed_signers
rm -- allowed-signers
```

The trusted file and its parent directories must remain root-controlled. A key
trusted for account A is not automatically trusted for account B. Rotating or
revoking a signing key is a deliberate local administrator action on every target:
verify the replacement fingerprint through a trusted channel, then update the
allowed-signers file. Do not lower the stored import revision when rotating trust.

## Export, review and push

Clone your **separate private sync repo** normally. Do not use this public source
checkout. Start with a positive revision and increase it for every new snapshot.
Keep track of the highest signed revision across all your machines; a revision
must never be reused, even after restoring backups or deleting Git history.

From the suite checkout:

```sh
./install.sh --sync export --repo /path/to/private-sync-checkout \
  --user "$(id -un)" --revision 1 \
  --signing-key "$HOME/.ssh/omarchy-enrollment-signing"
```

This exports the selected user's entries from `/etc/fido2/fido2`, validates them
and signs the exact JSON snapshot using the dedicated OpenSSH namespace. No
private signing key is copied. It creates two files with mode 0600:

- `omarchy-yubikey-enrollment.json`
- `omarchy-yubikey-enrollment.json.sig`

Review the changes locally, then `git add`, commit and push **only those two files**
from the private repo. No Git command should use sudo. For the next export, review
and remove the old export pair from that checkout before running export with a
strictly higher revision; Git will record the replacements. Export refuses to
overwrite an existing file or follow an export-file symlink.

An export with zero entries is an explicit revocation snapshot for that account;
it removes that account's key mappings on import. Other users are unaffected.

## Fetch and import

Keep a working password and a separate recovery root shell open. On the target,
fetch/pull the private repo as your normal user. Treat the downloaded contents as
untrusted until signature verification. For the **first import**, obtain the
minimum acceptable revision from your exporting machine or another trusted channel.
The repo cannot prove that an attacker is not withholding a newer snapshot.

From the suite checkout, preview (replace `1` with the known minimum):

```sh
./install.sh --sync import /path/to/private-sync-checkout/omarchy-yubikey-enrollment.json \
  --user "$(id -un)" --minimum-revision 1
```

The sibling `.sig` is required. The tool verifies the exact bytes against pinned
trust, checks account/origin/schema/options and shows revision, credential counts
and SHA-256 identifiers for additions/removals. It never prints raw credentials.
Preview does not install mappings; the CLI may create its private transaction lock.

Apply the reviewed snapshot:

```sh
./install.sh --sync import /path/to/private-sync-checkout/omarchy-yubikey-enrollment.json \
  --user "$(id -un)" --minimum-revision 1 --apply
```

Type the displayed `IMPORT ACCOUNT revision N` phrase at the terminal. This replaces
all key mappings for that account, including removals, and preserves other users.
It does not alter PAM policy or enable key authentication on a new machine; set
up and test matching PAM services separately. Test your key and password routes
before closing the recovery shell.

After a successful import, the root-only state file under
`/var/lib/omarchy-yubikey/sync-state.json` rejects the same or any lower revision.
For later imports, `--minimum-revision` is optional; it can impose a higher floor.
There is no background import, automatic acceptance, merge of remote credentials
or bypass flag for an old snapshot. Concurrent CLI imports/PAM setup/rollback use
the same root-controlled transaction lock.

## Recovery and limitations

Each applied import creates a private backup using the suite's existing backup
format. `./install.sh --rollback BACKUP_ID` restores mappings only if the
transaction targets have not changed since; later account enrollments stop the
rollback before writing. Legacy backups require manual review. Rollback deliberately
preserves the accepted sync high-water mark. Restoring mappings can itself
re-enable old keys; review this recovery action and issue a **newer signed
snapshot** to establish the intended current state.

Ordinary write errors roll back the mapping and import state together. Sudden
power loss or process termination between the two writes can leave the revision
advanced while the old mapping remains; this fails against replay rather than
silently accepting an old snapshot. Restore the mapping backup if needed and
export a newer revision. Do not delete or rewind the state file to work around it.

A fresh machine, a deleted state file or restoration of an entire old system
backup cannot know the latest accepted revision. Recover the minimum through a
trusted channel. An attacker who controls the remote can withhold data or cause
denial of service even without being able to forge signatures. Compromise of the
trusted signing key or root remains outside the guarantees of this workflow.
