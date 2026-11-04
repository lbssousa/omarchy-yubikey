# Translation catalogs

`en.json` is the canonical source; every registered language has the same keys.
Keep source code and comments English, and place translated text only in catalogs.
Use complete sentences with `%1`-style placeholders. Preserve technical literals,
product names, commands, paths and confirmation words.

The locale registry and matching shared UI translations derive from Omarchy at
commit `5f2fb785562b2b6cd9a58787a3bfd673568fe9dd`, under its MIT license. The
project-specific translations began with machine assistance and have structural
tests; they have not all been reviewed by native speakers. See
[third-party notices](../THIRD_PARTY_NOTICES.md) and
[language maintenance](../docs/languages.md).

`scripts/sync-i18n.py` copies only the necessary strings and loader into each
plugin and generates `pam/translations.h`. Edit these source catalogs and
`runtime/`, then regenerate; do not edit the generated copies.
