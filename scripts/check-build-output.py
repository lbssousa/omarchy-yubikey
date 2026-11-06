#!/usr/bin/env python3
"""Regression check for RUSTSEC-2026-0418 using synthetic environment values.

Build only the real locked zlib dependency in a fresh target directory. Check both
verbose Cargo output and its persisted build-script stdout, without printing
either stream (which could contain inherited values if the regression returns).
"""
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main():
    canaries = {
        'OMARCHY_BUILD_CANARY': 'synthetic-build-canary-alpha-0418',
        'OMARCHY_BUILD_MULTILINE': 'synthetic-build-canary-beta-0418\n"quoted"=value',
    }
    with tempfile.TemporaryDirectory(prefix='omarchy-build-output-') as temporary:
        target = Path(temporary)
        result = subprocess.run(
            ['cargo', 'build', '--locked', '-vv', '-p', 'libz-sys', '--target-dir', str(target)],
            cwd=ROOT, env=dict(os.environ, **canaries),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if result.returncode:
            raise SystemExit('zlib regression build failed; captured output was withheld')
        outputs = list((target / 'debug' / 'build').glob('libz-sys-*/output'))
        if not outputs:
            raise SystemExit('zlib regression build produced no build-script output')
        streams = [result.stdout, *(path.read_bytes() for path in outputs)]
        for value in canaries.values():
            marker = value.split('\n', 1)[0].encode()
            if any(marker in output for output in streams):
                raise SystemExit('Synthetic environment canary leaked into Cargo build output')
        if not any(b'cargo:rustc-link-lib=z' in path.read_bytes() for path in outputs):
            raise SystemExit('The dynamic/system-zlib probe was not exercised')
    print('Build-output regression check passed (verbose log and persisted stdout)')


if __name__ == '__main__':
    main()
