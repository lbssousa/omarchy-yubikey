# Contributing

Keep changes focused and state which component they affect. Include the
Omarchy, Quickshell, pam-u2f and libfido2 versions relevant to your change.
Never attach enrollment data, encrypted secret stores, accessibility dumps or
unredacted journals. Use synthetic credentials and generic device labels.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
node --test tests/*.test.cjs
python3 scripts/check-publication.py
python3 -m unittest discover -s tests -p 'test_*.py'
for script in install.sh scripts/install-plugins.sh scripts/build-pam-gate.sh luks/zzzz-omarchy-yubikey-luks.conf; do
  bash -n "$script"
done
```

On a compatible Omarchy installation, also run:

```sh
omarchy plugin validate plugins/yubikey.lock
omarchy plugin validate plugins/yubikey.polkit
```

The Rust tests cover encrypted-store round trips, tamper/wrong-key rejection
and file permissions. JavaScript tests cover the Polkit prompt model and lock
authentication routing. Python tests cover PAM planning, mapping merges,
backups, rollback, interrupted writes and plugin-copy behavior. CI cannot
establish real hardware authentication or safe session-lock recovery. Describe
manual checks separately and do not claim a hardware route was tested when
only a mock or static check ran.

Native PAM tests need Linux-PAM headers and a C compiler (Arch: `base-devel pam`;
Debian/Ubuntu: `build-essential libpam0g-dev`). They load the actual fallback gate
in an isolated `pam_start_confdir` stack with synthetic key/password modules,
never the system authentication configuration. Signed-transfer tests use disposable
OpenSSH keys and real `ssh-keygen -Y` signatures. No real mappings belong in fixtures.

LUKS tests use synthetic metadata and mocked commands. Never point a test at a
real disk or hardware key. Enrollment and boot-image/reboot qualification are
separate manual checks; preserve the passphrase and a bootable fallback image.

Test lock changes on a disposable profile or recoverable machine, while keeping
password access available. Do not replace the active lock implementation during
a locked session. Changes to relying-party IDs or crypto contexts require an
explicit enrollment migration plan.

## Writing conventions

Use English for source comments, CLI help, prompts, notifications, error
messages and documentation. Keep wording concise and consistent: use
"security key" for generic FIDO2 devices, "YubiKey" for the product, and
"keyring password" and "FIDO2 PIN" for the two distinct secrets. Comments should
explain intent, constraints or non-obvious behavior, and match the implementation.

Preserve the MIT license and Omarchy attribution. Security findings belong in
the private reporting channel, not a public issue.
