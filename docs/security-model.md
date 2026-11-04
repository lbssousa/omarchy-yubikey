# Security model

This document describes the current implementation, not a certification or a
completed security audit. Release numbers identify published versions, not
independent security certification or hardware compatibility qualification.

## PAM authentication

The default sudo/Polkit configuration uses `pam_u2f` as a sufficient method with
`pinverification=1 userpresence=1`. A FIDO2 PIN must already be set. Touch-only is
an explicit installer alternative; in that mode, anyone holding the registered
key and accessing an eligible session may be able to authorize requests. A touch
is never proof that you reviewed the command being authorized.

With the default explicit fallback policy, unsuccessful key authentication reaches
a `requisite` conversation gate. Only the literal response `password` permits
continuing to the existing password stack. The gate never authenticates a user;
never configure it as sufficient or as a standalone authentication stack.
Conversation failures, cancellation, a missing gate and silent operation fail
closed. An absent or ignored key can still be followed by password authentication,
but only after confirmation. Automatic fallback remains an explicit installer choice.
`authpending_file` is pam-u2f's touch-notification mechanism, not a fallback policy.

Password fallback is deliberate. This configuration is not mandatory two-factor
authentication and does not prevent password-based login. sudo timestamp caching
still applies. Existing PAM policy and account checks may impose extra rules.
The dedicated screen-lock FIDO2 service uses `required`. The lock starts only the
selected method; it routes each PIN response to that key conversation and never
reuses it as an account password. A failed key attempt stays in key mode until a
user selects a retry or another method. Fingerprint is also an explicit selection.

The central mapping is root-owned, readable by local users and contains public
credential information. Changing it requires root. The shell plugins themselves
run inside the authentication-capable Omarchy host and must be trusted.

Optional [enrollment transfer](enrollment-sync.md) signs per-account snapshots with
OpenSSH. Imports verify a locally pinned signer for that account and namespace,
validate the schema and credential options, and require an interactive review.
Git runs separately as the normal user; PAM reads a root-owned installed copy.
Accepted revisions form a local high-water mark. This prevents replay of accepted
or older revisions, not withholding a newer release. A new machine needs a minimum
revision obtained through a trusted channel. Backups/rollback preserve the sync
high-water mark after a completed import. A crash between state and mapping writes
can require restoring the mapping backup and issuing a newer signed revision.
Signatures provide integrity, not confidentiality: use a separate private repo.
The signing key holder can authorize account credentials; protect that key and
bootstrap/rotate trust outside the synced repository.

## Helper encryption and secret use

The helper enrolls a nonresident ES256 credential with `hmac-secret`. A random
32-byte salt and a touched assertion produce key material. HKDF-SHA256 derives
a key with a helper-specific context; ChaCha20-Poly1305 encrypts the saved secret
using a fresh 12-byte nonce. The credential ID is authenticated as associated
data. The disk store contains the credential ID, salt, nonce, ciphertext, a label
and timestamp; the derived encryption key is not saved.

PAM PIN mode does not change the independent helper. The helper requests user presence without user verification during normal
unlock. Possession of the key and a copied store can be enough to recover the
saved secret. File encryption is not protection from malicious code already
running as the same user while the secret is in use, or from root.

GNOME Keyring receives the recovered password over a **plain Secret Service
session** on the local user D-Bus, using a GNOME internal API. Password buffers
and derived keys use zeroizing wrappers in several places; there is no guarantee
against every copy, swap, core dump, bus observation or desktop compromise.

The helper store uses an atomic temporary-file rename and requests 0700 directory
and 0600 file modes on creation. Existing directories/files, symlinks and a custom
store path must still be controlled by the user. Do not point a store into an
untrusted or shared directory.

## Desktop limitations

The Polkit UI detects direct module names in one PAM file. It is a presentation
hint, not authoritative discovery of the full PAM stack. The lock handles actual
PAM success/failure separately. Host updates can break QML imports, IPC contracts
or the lock lifecycle; test password unlock and recovery after updates.

## LUKS disk unlock

Optional LUKS2 enrollment delegates cryptography and credential storage to
systemd and cryptsetup. It requests client PIN and user presence; these depend
on the key supporting/enforcing them. The existing disk passphrase remains an
alternative, so this does not require two factors on every unlock path.
Unlike the PAM touch-only route, the intended disk-token policy is PIN plus
touch. Verify that behavior on your own key and boot environment.

The LUKS2 header stores token metadata and protected key material. Before/after
header backups are private, sensitive recovery artifacts. Old backups may
retain access through credentials later removed from the live header. Never
commit them or share raw header dumps. The wizard does not save PINs or disk
passphrases, but systemd displays a newly generated recovery key in the terminal;
do not record or upload that output.

Boot integration is a separate manual step. Enrollment tests do not establish
that the correct keyboard, crypttab, FIDO2 libraries or snapshot/resume support
made it into the boot image. Preserve a bootable fallback and test both key and
absent-key/passphrase boots. This feature does not enable Secure Boot or protect
an unsigned, writable boot environment from physical tampering. See [LUKS](luks.md).

## Local data and reporting

Never publish PAM mapping files, encrypted helper stores, credential handles,
key serial numbers, personal labels, journals or accessibility dumps without
review. LUKS headers, UUIDs, recovery keys, boot images and extracted crypttab
files also belong outside the repository. See [publication](publication.md) for the repository checks. Do not put
real credentials in tests: existing crypto tests use synthetic bytes only.

Report suspected vulnerabilities privately through the process in
[SECURITY.md](../SECURITY.md). No hardware matrix or independent security audit
has been completed for this extracted version.

## Setup control center

The `yubikey.setup` UI reads bounded local metadata. It does not receive PINs,
passwords, serial numbers, credential values or child command output. Fixed
action names and validated argument arrays select local scripts; no user field
is interpolated into a shell command. Operations run in an interactive terminal
as the account user, with sudo requested only by the selected installer/tool.
A private state directory, lock and expiring launch ticket coordinate operations.
They are not a defense against arbitrary code already running as that user.

PAM key management changes only the selected account's mapping. Removal requires
an exact, unambiguous reference, preserves at least one key, recalculates under
the system configuration lock and uses existing transactional backups. Restore
checks applied hashes/modes before writing, protecting later account changes.
The login-service toggle accepts only a regular unit matching the reviewed
shipped service. Disable/remove of the setup window does not undo security
configuration; see [component recovery](control-center.md#recovery-and-removal).
