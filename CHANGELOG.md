# Changelog

## Unreleased

- OpenPGP card: one button imports a missing key or removes an imported one,
  instead of always showing both. A separate **Update key** button appears only
  when the imported key is not linked, expired, revoked or disabled.

- Fix translations of the standalone lock and Polkit plugins on Omarchy 4.5,
  whose `qs.Commons` exports its own `Translations` type. Their unqualified
  `Translations` resolved to it instead of the bundled loader, as the setup
  window's did before 0.5.0, so they stayed in English, lost right-to-left layout
  and failed on `strings.number`. They now import the bundled loader by a
  qualified local import.

- Tests: the PAM setup and key-removal tests pin English, as the installer
  tests already do. They matched English messages that `tr()` translated into
  the developer's own Omarchy language, so four of them failed on any non-English
  desktop.

## 0.5.2 — 2026-11-06

- Integrate the reviewed Dependabot batch in PRs #5–#15: pinned checkout 7.0.1,
  Rust build/FFI/procedural-macro dependencies and chacha20poly1305 0.11.
- Explicitly retain key/state zeroization for the crypto update and add a
  compile-time regression guard. Verify decryption of a synthetic v1 store
  produced with chacha20poly1305 0.10.1, including rejection of wrong keys,
  changed credentials and modified ciphertext.
- Group routine minor/patch version updates while keeping crypto/hardware-auth
  and major changes separate. Leave security updates outside routine groups.

## 0.5.1 — 2026-11-06

- Update the locked `libz-sys` dependency from 1.1.30 to 1.1.31 for
  RUSTSEC-2026-0418. Unix builds no longer print the inherited compiler
  environment during the dynamic-zlib probe. Normal native build settings remain
  available for installer, CI and manual Cargo builds.
- Replace yanked `async-executor 1.14.0` with 1.14.1, fixing the upstream
  use-after-free regression during executor shutdown.
- Add a real build-output regression check with synthetic environment canaries,
  weekly Dependabot updates for direct/transitive Cargo dependencies and GitHub
  Actions, and daily RustSec audits of the locked dependency graph.

## 0.5.0 — 2026-11-06

- Import the OpenPGP key stored on a connected card into the account's GnuPG
  keyring after matching all populated card fingerprints in an isolated staging
  keyring. Report actual card links per slot, local secrets, revocation and
  expiry; keep ownertrust separate. Removal refuses local secret material and
  rechecks after confirmation.
- Copy the resident SSH keys of the security key into `~/.ssh` (`ssh-keygen -K`
  in a private directory, never over an existing file). Require matching key
  pairs and remove by stable identity with a post-confirmation file check.
- Manage opted-in Git hosts in `~/.ssh/omarchy-yubikey/config` with a global
  Include, effective `ssh -G` previews, manual-edit detection and reviewed
  updates on import/removal/reimport. Connection reuse defaults to off and
  explicitly overrides inherited multiplexing settings.
- Show bounded, selectable public fingerprints and SSH applications, with
  OpenPGP name/email hidden until requested. Keep card serials, filenames and
  credential handles outside the window.
- Resolve the bundled setup translation loader explicitly on Omarchy 4.5.

## 0.4.0 — 2026-11-04

- Add the root `yubikey.setup` marketplace plugin: bar entry and native window
  for status, keys, desktop authentication, GNOME Keyring, LUKS and PAM recovery.
- Keep authentication responses in explicit terminal actions, validate fixed
  argument vectors and prevent concurrent launches with private operation state.
- Add per-account PAM key addition/removal with versioned backups, preserving
  other accounts and refusing removal of the last or an ambiguous registration.
- Add component-specific setup, read-only backup listing and preservation of
  existing Keyring enrollments on helper setup.
- Provide English/German setup UI, responsive layouts, keyboard confirmation
  defaulting to Cancel, synthetic previews and native Quickshell checks.
- Keep standalone lock/Polkit plugins at 0.3.0 and Rust helper at 0.2.0.

## 0.3.0 — 2026-11-04

- Add all 50 Omarchy languages to the Keyring helper, guided setup, enrollment
  tools, PAM fallback prompt and desktop plugins, with English fallback.
- Follow per-account language choices, support live shell language changes and
  right-to-left layouts, and keep commands and confirmation literals stable.
- Bundle plugin catalogs in standalone exports and embed helper/PAM translations
  for offline use; validate catalog completeness and placeholder integrity.
- Protect shared PAM policy changes when other accounts are enrolled.
- Refuse stale or legacy automatic rollback before writing, preserving later
  account enrollments and permission changes.
- Release shell plugins at 0.3.0 and the Keyring helper at 0.2.0; existing
  credentials and encrypted stores remain compatible.

## 0.2.1 — 2026-11-04

- Standardize Keyring helper help, prompts, notifications, errors and source
  comments in English.
- Update the README and Keyring guide, clarify comments and document contribution
  writing conventions.
- Release the Keyring helper as 0.1.1; existing enrollment stores remain
  compatible. Standalone shell plugins remain at 0.2.0.

## 0.2.0 — 2026-11-04

- Default new PAM setup to PIN plus touch and explicit password fallback.
- Add a locally built, fail-closed PAM confirmation gate before the existing
  password stack; preserve deliberately selected touch-only/automatic modes.
- Route lock PINs only to the selected key conversation, add method buttons and
  stop automatic method switching/PIN retries after failure.
- Show actual Polkit PIN/password prompts and an explicit fallback button.
- Qualify shell color singletons to avoid collisions with newer Qt color types.
- Add opt-in signed per-account enrollment export/import with private Git as
  user-managed transport, pinned trust, review, revision checks and rollback.
- Test actual Linux-PAM conversations and real OpenSSH signatures in isolation.
- Publish updated standalone plugins at 0.2.0; leave Keyring helper at 0.1.0.

## 0.1.1 — 2026-11-03

- Add separate opt-in LUKS2 enrollment with explicit device selection, PIN plus
  touch, private header backups, optional backup/recovery keys and slot preservation.
- Verify newly added tokens without creating a second mapping of a mounted disk.
- Document manual mkinitcpio/Limine boot integration, a preserved fallback image,
  snapshot/resume support, absent-key password fallback and rollback.
- Include an optional hook-conversion drop-in that retains hardware choices
  and rejects unknown hooks, with isolated regression tests.
- Extend privacy checks for disk identifiers and boot/runtime artifacts.
- Leave desktop plugins and the Rust helper unchanged at component version 0.1.0.

## 0.1.0 — 2026-11-03

- Extract PAM examples, the FIDO2-aware Polkit dialog and the parallel-flow lock
  plugin into an independent source repository.
- Include an optional Rust helper for GNOME Keyring.
- Use neutral plugin IDs and project-owned FIDO relying-party identifiers;
  prototype stores require fresh enrollment.
- Add a guided installer with feature selection, key enrollment, conservative
  PAM changes, backups, rollback and optional Keyring startup integration.
- Add setup, rollback, security, contribution and publication documentation.
- Add automated software checks and synthetic regression coverage.
- Publish standalone distribution repositories for the lock and Polkit plugins.
- Include source archives and SHA-256 checksums; no prebuilt executables.

The validation scope and remaining hardware checks are documented in the release notes.
