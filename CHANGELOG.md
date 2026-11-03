# Changelog

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

The validation scope and remaining hardware checks are documented in the release notes.

- Publish standalone distribution repositories for the lock and Polkit plugins.
- Include source archives and SHA-256 checksums; no prebuilt executables.
