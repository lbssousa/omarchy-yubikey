# Languages

The Keyring helper, guided installer, enrollment tools, lock screen and Polkit
plugin ship catalogs for all 50 Omarchy languages, including English. Comments,
command names, options, file paths and developer documentation remain English.

The new 0.4.0 control-center window has separate English/German catalogs under
`i18n/control/`. It follows the same language choice and uses English fallback
for other languages; this does not expand the existing standalone catalogs.
New key-management and component-setup prompts use English where the existing
catalogs do not have a translation.

## Language selection

The desktop plugins follow **Setup > Language**, including live changes while
open. Arabic, Hebrew, Persian and Urdu use right-to-left layouts. Native
`Commons.Translations` is used on newer shells; a compatibility loader reads the
same per-account language file on older hosts.

The command-line tools read the account's Omarchy language selection from
`$XDG_CONFIG_HOME/omarchy/language` (normally `~/.config/omarchy/language`). Without
a selection, they use `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, then `LANG`. Unknown
languages fall back to English. Regional locales such as `de_AT.UTF-8` resolve
to their supported language; `pt_BR` and `zh_TW` retain their regional catalogs.
Missing entries fall back to the base language and then English.

For an explicit helper override:

```sh
keyring-unlock --language de --help
keyring-unlock --language ja status
```

For the installer:

```sh
OMARCHY_YUBIKEY_LANGUAGE=fr ./install.sh
```

Python enrollment tools also accept `--language CODE`. The installer passes the
resolved code through sudo explicitly, so root's language does not replace the
account's selection. The compiled PAM fallback gate uses its process locale;
it embeds its translations and does not read user-controlled catalog files.

Only display text changes. Command names, argument values, credential formats,
PAM results and IPC values stay stable. The confirmation words `password`,
`ENROLL`, and signed-import confirmation text remain literal in every language.
Confirmation questions retain `y`/`n` responses. Unknown prompts supplied by PAM
or Polkit are displayed as received. Parser diagnostics and third-party command
output follow those programs' own language support.

## Maintaining translations

The canonical catalogs are `i18n/en.json` and one matching JSON file per language.
Keys are complete English sentences, with `%1`, `%2`, etc. for substituted
values. Every catalog must have the same keys and placeholders. Values are
inserted once and displayed as plain text; paths and account names cannot become
format strings or markup.

`i18n/locales.json` mirrors the 50-language registry from
[Omarchy's localization source](https://github.com/omacom/omarchy/blob/5f2fb785562b2b6cd9a58787a3bfd673568fe9dd/default/i18n/locales.json).
The regional conventions follow Omarchy: Mexican Spanish, European and Brazilian
Portuguese, Norwegian Bokmål, Cyrillic Serbian, Simplified Chinese and Traditional
Chinese for Taiwan.

The initial catalogs use existing Omarchy translations where messages match and
machine-assisted translations for project-specific messages. Automated checks
establish completeness and structural correctness, not native-speaker review
of every sentence. Language corrections are welcome; preserve commands, paths,
product names, confirmation literals and placeholders.

After changing catalogs or the shared QML loader, regenerate the distributable
plugin catalogs and embedded PAM prompt table:

```sh
python3 scripts/sync-i18n.py
python3 scripts/sync-i18n.py --check
python3 -m unittest discover -s tests -p 'test_*.py'
node --test tests/*.test.cjs
cargo test --workspace --locked
```

The Rust helper embeds the catalogs at build time and needs rebuilding after a
translation change. Plugins carry their own catalogs, so both suite installs
and standalone plugin repositories work without the suite checkout.
