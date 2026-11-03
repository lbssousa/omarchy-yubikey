# Security policy

The current release series is **0.1.x**. Fixes are made on `main` and included
in subsequent releases. Report issues against the latest available version.
Hardware authentication and session locking also need validation on the target
environment; see the documented validation scope and security model.

Please use the repository's **Security → Report a vulnerability** feature when
available. If it is not available, open an issue asking for a private reporting
channel without posting exploit details, personal data or credentials. A
response deadline is not guaranteed for this community project.

Include affected versions, expected versus observed behavior and a minimal
reproduction with synthetic data. Never include enrolled credential mappings,
encrypted password stores, real secrets or unredacted logs.

For the current assumptions and limitations, read
[the security model](docs/security-model.md).
