# Security model

This document describes the current implementation, not a certification or a
completed security audit. Release numbers identify published versions, not
independent security certification or hardware compatibility qualification.

## PAM authentication

The provided sudo/Polkit line uses `pam_u2f` as a sufficient authentication
method before the existing password stack. It authenticates a registered key
with a touch; it does not request a FIDO2 PIN or biometric verification. Anyone
with the key and access to an eligible session may be able to authorize a
request. A key touch is not proof that you reviewed the command being authorized.

Password fallback is deliberate. This configuration is not mandatory two-factor
authentication and does not prevent password-based login. sudo timestamp caching
still applies. Existing PAM policy and account checks may impose extra rules.
The dedicated screen-lock FIDO2 service uses `required`; password auth remains
in its own parallel service.

The central mapping is root-owned, readable by local users and contains public
credential information. Changing it requires root. The shell plugins themselves
run inside the authentication-capable Omarchy host and must be trusted.

## Helper encryption and secret use

The helper enrolls a nonresident ES256 credential with `hmac-secret`. A random
32-byte salt and a touched assertion produce key material. HKDF-SHA256 derives
a key with a helper-specific context; ChaCha20-Poly1305 encrypts the saved secret
using a fresh 12-byte nonce. The credential ID is authenticated as associated
data. The disk store contains the credential ID, salt, nonce, ciphertext, a label
and timestamp; the derived encryption key is not saved.

The helper requests user presence without user verification during normal
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
