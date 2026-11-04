"""Exercise component routing in a real PTY with changes cancelled before sudo."""
import fcntl
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerComponentTests(unittest.TestCase):
    def cancelled(self, component, answers):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            binaries = home / 'bin'
            binaries.mkdir()
            marker = home / 'unexpected-command'
            for name in ('pacman', 'sudo', 'pamu2fcfg'):
                path = binaries / name
                path.write_text('#!/bin/sh\ntouch "$HOME/unexpected-command"\nexit 99\n')
                path.chmod(0o755)
            master, slave = pty.openpty()
            def terminal():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            environment = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'),
                               XDG_STATE_HOME=str(home / 'state'), OMARCHY_YUBIKEY_LANGUAGE='en',
                               PATH=str(binaries) + os.pathsep + os.environ['PATH'])
            process = subprocess.Popen(['bash', str(ROOT / 'install.sh'), '--components', component],
                                       stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal,
                                       env=environment, close_fds=True)
            os.close(slave)
            try:
                os.write(master, answers.encode())
                data = bytearray()
                deadline = time.monotonic() + 10
                while process.poll() is None and time.monotonic() < deadline:
                    if select.select([master], [], [], .1)[0]:
                        try:
                            data.extend(os.read(master, 65536))
                        except OSError:
                            break
                code = process.wait(timeout=2)
                self.assertEqual(code, 0, data.decode(errors='replace'))
                self.assertFalse(marker.exists(), 'An installer command ran despite cancellation')
                return data.decode(errors='replace')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)

    def test_sudo_only_does_not_offer_desktop_or_keyring(self):
        output = self.cancelled('sudo', 'y\ny\nn\n')
        self.assertIn('Continue with key enrollment', output)
        self.assertNotIn('Add desktop touch prompts', output)
        self.assertNotIn('Also install the optional', output)
        self.assertNotIn('Desktop integration is unavailable', output)

    def test_keyring_only_does_not_offer_pam_changes(self):
        output = self.cancelled('keyring', 'n\n')
        self.assertIn('Continue with touch-only Keyring enrollment?', output)
        self.assertNotIn('Continue with key enrollment', output)
        self.assertNotIn('Enable security-key authentication for sudo?', output)
        self.assertNotIn('Desktop integration is unavailable', output)


if __name__ == '__main__':
    unittest.main()
