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
3. Run Gitleaks against both the working directory and Git history. Review
   findings locally; do not upload a report containing unredacted values.
4. Inspect every image. The supplied SVG is original illustrative artwork, not
   a desktop screenshot. Do not add a screenshot with real accounts, commands,
   notifications, machine names or device identifiers.
5. Review commit names/emails, branches and tags. Confirm repository visibility
   is still **private** until publication is explicitly intended.

The lightweight publication script is an additional guard, not a complete
secret detector or anonymization guarantee. `.gitignore` does not protect a
file already tracked. Never force-add ignored runtime data.

Before making the source preview public, qualify the renamed plugins on a fresh
Omarchy profile, enroll new test credentials, test real sudo/Polkit/key unlock,
test absent-key/password fallbacks, cancel/timeout, suspend/resume, multiple
displays and backup-key recovery. Verify the optional helper against current
GNOME Keyring versions without exposing enrollment data.
