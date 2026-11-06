# OpenPGP key on the security key

The **OpenPGP key on the card** card on the *Security keys* page operates on
the desktop account's GnuPG keyring, without privileges. Every operation opens
an interactive terminal. PINs go to GnuPG's pinentry, never to the setup window.

The window shows the public primary fingerprint (selectable for copying),
algorithm, usable capabilities, expiry and user-ID count. **Show name and
email** optionally reveals the primary valid public user ID. These fields
are bounded, stripped of control characters and rendered as plain text.
Card serials and card URLs remain outside the window.

The sign, encrypt and authenticate slots retain their roles even when an
earlier slot is empty. Each populated slot reports whether its secret is on
this card, on another card, on disk or missing. A local secret is not a card
link. A primary secret on disk can coexist with card subkeys: the local copy
is reported separately and each slot is checked independently.

**Ready** means all populated card slots have matching GnuPG card references
and usable public keys. Expired, revoked and disabled keys are not ready.
Ownertrust is shown separately; ultimate ownertrust is not a prerequisite for
using your card and does not prove a hardware link.

**Import key** and **Remove from keyring** share one button: it imports while the
key is missing and removes it once it is in the keyring.

| Action | What happens in the terminal |
| --- | --- |
| **Import key** | Fetches into a private temporary GnuPG home using the card URL (HTTP, HTTPS, HKP or HKPS), falling back to a keyserver. Only a public certificate containing every populated card-slot fingerprint is exported into the account's keyring. Other downloaded certificates stay in the temporary keyring. A successful fetch of the wrong key triggers fallback. The account's configured dirmngr keyserver URLs are carried into staging; arbitrary GnuPG configuration is not. GnuPG then reads the card to create references; a changed card or a local secret preventing a link is reported. Local secrets are never replaced. |
| **Update key** | Shown only when the imported key needs attention: not linked to the card, expired, revoked or disabled. Runs the same fetch as **Import key**, which refreshes the public certificate (for example after its expiry was extended) and the card references. |
| **Trust as my key** | Marks the displayed primary key as ultimately trusted after a separate confirmation. Only do this for your own key. |
| **Remove from keyring** | Requires a typed confirmation and deletes the public certificate and card stubs, leaving the card unchanged. Removal refuses if any secret part of that certificate is on disk. The secret listing is checked again after confirmation; an inspection failure also stops removal. |

Set the card URL with `gpg --card-edit` (`admin`, `url`) to support import
without a keyserver. Existing keyserver configuration belongs in dirmngr.
The temporary agents are stopped before the staging directory is removed.

Software tests cover synthetic per-slot listings and isolated real GnuPG
keyrings. Signing, decryption, pinentry and reader behavior still require
testing with the target card and GnuPG version.
