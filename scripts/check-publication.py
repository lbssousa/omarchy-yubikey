#!/usr/bin/env python3
"""Check Git-tracked publication content; never print matched secret values."""
from pathlib import Path, PurePosixPath
import hashlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_ROOTS = {
    ".editorconfig", ".gitattributes", ".gitignore", "Cargo.toml", "Cargo.lock",
    "rustfmt.toml", "install.sh", "LICENSE", "README.md", "THIRD_PARTY_NOTICES.md",
    "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "manifest.json", "ControlCenter.qml", "preview.png",
}
ALLOWED_DIRS = {".github", "assets", "docs", "keyring-unlock", "plugins", "pam", "scripts", "systemd", "tests", "luks", "i18n", "ui"}
DENIED_PARTS = {".env", ".ssh", ".aws", ".config", ".local", "target", "node_modules", "__pycache__"}
DENIED_NAMES = {"password.json", "u2f_keys", "fido2", "omarchy-enrollment", "crypttab", "crypttab.initramfs", "machine-id", "omarchy-yubikey-enrollment.json", "omarchy-yubikey-enrollment.json.sig", "sync_allowed_signers", "sync-state.json", "sync.lock"}
DENIED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".bundle", ".log", ".bak", ".tmp", ".sqlite", ".db", ".eml", ".img", ".efi", ".cpio", ".initramfs", ".jsonl"}
PATTERNS = {
    "absolute user home path": re.compile(rb"/(?:home|Users)/[A-Za-z0-9_.-]+/"),
    "private network address": re.compile(rb"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    "private key block": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
}
EMAIL = re.compile(rb"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UUID = re.compile(rb"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
# The sole permitted UUID is an explicitly synthetic test fixture.
SYNTHETIC_UUID = b"00000000-0000-4000-8000-000000000000"

# Visually reviewed synthetic UI capture; changing it requires renewed review.
REVIEWED_ASSETS = {"preview.png": "3e02f58fad9df91c72097964c7c2b04257db56a547cebec780accba35e36a908"}

def publication_content_failures(name, data):
    if name in REVIEWED_ASSETS:
        return [] if hashlib.sha256(data).hexdigest() == REVIEWED_ASSETS[name] else ["preview changed; explicit visual/privacy review required"]
    return content_failures(data)

def content_failures(data):
    reasons = [label for label, pattern in PATTERNS.items() if pattern.search(data)]
    if b"\0" in data:
        reasons.append("binary file needs explicit manual review")
    if any(value.lower() != SYNTHETIC_UUID for value in UUID.findall(data)):
        reasons.append("non-synthetic UUID")
    if any(not address.endswith(b"@users.noreply.github.com") for address in EMAIL.findall(data)):
        reasons.append("non-noreply email address")
    return reasons

def main():
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    names = [n.decode() for n in raw.split(b"\0") if n]
    if not names:
        sys.exit("No tracked files: stage the intended publication content first.")
    failures = []
    for name in names:
        path = PurePosixPath(name)
        if path.parts[0] not in ALLOWED_DIRS and name not in ALLOWED_ROOTS:
            failures.append((name, "unexpected publication path"))
        if any(p in DENIED_PARTS for p in path.parts) or path.name in DENIED_NAMES or path.suffix in DENIED_SUFFIXES or ".bak" in path.name:
            failures.append((name, "runtime, backup or credential filename"))
        file = ROOT / name
        if file.is_symlink():
            failures.append((name, "symlink"))
            continue
        if not file.is_file():
            failures.append((name, "missing file"))
            continue
        data = file.read_bytes()
        failures.extend((name, reason) for reason in publication_content_failures(name, data))
    for name, reason in failures:
        print(f"FAIL {name}: {reason}", file=sys.stderr)
    if failures:
        return 1
    print(f"Publication checks passed for {len(names)} tracked files.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
