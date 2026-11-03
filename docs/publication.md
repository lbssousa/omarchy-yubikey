# Publication and privacy checklist

This repository starts with fresh history and an explicit source selection.
It does not include the original home-directory tree or earlier development
history. The public GitHub handle is used for attribution; commit email uses
GitHub's noreply address.

Before every push or release:

1. Inspect `git diff --cached` and `git ls-files`. Include only source, synthetic
   tests, documentation, original artwork and project metadata.
2. Run `python3 scripts/check-publication.py`. It checks tracked paths and text
   for common local-data filenames, home paths, personal email addresses,
   private-network addresses and obvious credential patterns.
   It also rejects non-synthetic UUIDs and common LUKS/boot artifacts. The only
   permitted UUID is the explicitly synthetic fixture in the checker. Do not
   relax this rule to include a real machine identifier.
3. Run Gitleaks against both the working directory and Git history. Review
   findings locally; do not upload a report containing unredacted values.
4. Inspect every image. The supplied SVG is original illustrative artwork, not
   a desktop screenshot. Do not add a screenshot with real accounts, commands,
   notifications, machine names or device identifiers.
5. Review commit names/emails, branches and tags. Confirm repository visibility
   and that publication is explicitly intended. Use the existing public handle
   and GitHub noreply email for both author and committer attribution.

LUKS additions must be recreated as generic source, never copied wholesale from
local setup scripts or chat logs. Keep disk UUIDs, partition/device serials,
machine/account names, local paths, raw headers, header backups, recovery keys,
FIDO credential IDs, PINs, UKIs and extracted initramfs/crypttab files outside
the publication tree. Review the final archive member list and scan its exact
contents as well as the staged files and Git history. Release archives are built
from the reviewed Git tag, never by tarring the whole working directory.

The lightweight publication script is an additional guard, not a complete
secret detector or anonymization guarantee. `.gitignore` does not protect a
file already tracked. Never force-add ignored runtime data.

Personal signed enrollment exports and signatures, pinned signer files and local
sync revision state belong only in the separate private sync workflow. Never
publish them in this source tree or source-release archives. Tests must generate
disposable signing keys in temporary directories and delete them afterwards.

Before claiming a new hardware combination is qualified, test the plugins on a fresh
Omarchy profile, enroll new test credentials, test real sudo/Polkit/key unlock,
test absent-key/password fallbacks, cancel/timeout, suspend/resume, multiple
displays and backup-key recovery. Verify the optional helper against current
GNOME Keyring versions without exposing enrollment data.
