# OpenPGP key on the security key

Besides FIDO2 registrations for PAM, many security keys carry an OpenPGP card.
The control center brings its key into the account's own GnuPG keyring, as the
desktop user and without privileges. Like every other action, each one opens a terminal first;
PINs stay in that terminal.

The **OpenPGP key on the card** card on the *Security keys* page appears
while a key with an OpenPGP card is connected (`gpg --card-status`). Its badge
shows whether the key is imported, linked to the card and trusted. The window
receives only those flags, never the fingerprint, holder name, URL or serial.

| Action | What happens in the terminal |
| --- | --- |
| **Import key** | Shows the card holder and signature-key fingerprint, then fetches the public key from the URL stored on the card (`gpg --fetch-keys`; only `https`, `http`, `hkps` and `hkp` URLs) or else from the configured keyservers (`gpg --recv-keys`), and reads the card again so gpg creates the stubs that point at it. |
| **Trust as my key** | Marks the key as ultimately trusted (`gpg --import-ownertrust`) after a confirmation. Only do this for your own key. |
| **Remove from keyring** | Deletes the public key and the card stubs after you type the confirmation. The key stays on the card and can be imported again. It **refuses** when gpg keeps a secret part of the key on disk rather than only on the card, since removing it would lose that secret for good. |

Set the card URL with `gpg --card-edit` (`admin`, `url`) to make imports work
without a keyserver.
