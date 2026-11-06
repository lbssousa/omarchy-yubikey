#!/usr/bin/env python3
"""Render the native setup UI with synthetic data; never launch real actions."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = {'supported': True, 'connected': 1, 'enrollment': {'count': 2, 'state': 'enrolled'},
           'sudo': {'state': 'configured', 'pin': True, 'explicit': True},
           'polkit': {'state': 'configured', 'pin': True}, 'lock': {'state': 'configured', 'pin': True},
           'plugins': {'lock': {'installed': True, 'enabled': True}, 'polkit': {'installed': True, 'enabled': True}},
           'keyring': {'installed': True, 'state': 'enrolled', 'count': 2, 'unit': True, 'autostart': 'enabled'},
           'openpgp': {'card': True, 'imported': True, 'linked': True, 'trusted': False, 'ready': True,
                       'slots': {role: {'present': True, 'linked': True, 'ready': True, 'location': 'card'}
                                 for role in ('sign', 'encrypt', 'authenticate')},
                       'key': {'algorithm': 'ed25519', 'sign': True, 'encrypt': True, 'authenticate': True,
                               'expires': '2030-01-01', 'expired': False, 'uids': 2, 'fingerprint': 'A' * 64, 'uid': 'Synthetic User'}},
           'ssh': {'count': 2, 'keys': [{'id': 'a' * 64, 'type': 'ed25519-sk', 'passphrase': True, 'host': True, 'application': 'ssh:github.com', 'fingerprint': 'SHA256:' + 'A' * 43},
                                        {'id': 'b' * 64, 'type': 'ecdsa-sk', 'passphrase': False, 'host': False, 'application': 'ssh:', 'fingerprint': 'SHA256:' + 'B' * 43}]},
           'operation': {}, 'diskReady': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screenshots', type=Path)
    parser.add_argument('--width', type=int, default=1280)
    parser.add_argument('--height', type=int, default=900)
    parser.add_argument('--language', default='en', choices=['en', 'de', 'ar'])
    parser.add_argument('--shell-root', type=Path, default=Path('/usr/share/omarchy/shell'))
    args = parser.parse_args()
    if not shutil.which('qs') or not (args.shell_root / 'Commons').is_dir():
        parser.error('Run native UI checks on an Omarchy machine with Quickshell and QtTest installed')
    screenshots = args.screenshots.resolve() if args.screenshots else None
    if screenshots:
        screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='yubikey-ui-test-') as temporary:
        directory = Path(temporary)
        for name, source in {'Commons': args.shell_root / 'Commons', 'Ui': args.shell_root / 'Ui',
                             'Setup': ROOT / 'ui', 'i18n': ROOT / 'i18n',
                             'ControlPanelTest.qml': ROOT / 'tests/qml/ControlPanelTest.qml'}.items():
            (directory / name).symlink_to(source)
        runtime = directory / 'runtime'
        runtime.mkdir(mode=0o700)
        fixture = json.dumps(FIXTURE)
        output = json.dumps(str(screenshots) if screenshots else '')
        (directory / 'shell.qml').write_text('''import QtQuick
import Quickshell
import "Setup" as Setup
ShellRoot {
  FloatingWindow {
    implicitWidth: WIDTH
    implicitHeight: HEIGHT
    visible: true
    title: "YubiKey test fixture"
    Setup.ControlPanel { id: panel; anchors.fill: parent; snapshot: (FIXTURE) }
    Setup.BarWidget { visible: false }
    ControlPanelTest { id: tests; panel: panel }
    Timer {
      id: steps
      interval: 300; running: true; repeat: true
      property int step: -1
      onTriggered: {
        try {
          if (step === -1) { tests.test_actions_and_keyboard(); panel.page = 0; step = 0; return }
          if (step >= 5) { console.log("UI_TESTS_PASSED"); Qt.quit(); return }
          if (OUTPUT !== "") {
            running = false
            panel.grabToImage(function(image) {
              if (!image.saveToFile(OUTPUT + "/page-" + steps.step + ".png")) throw new Error("Capture failed")
              steps.step++; panel.page = Math.min(steps.step, 4); steps.running = true
            })
          } else { step++; panel.page = Math.min(step,4) }
        } catch (error) { console.error("UI_TESTS_FAILED", error); Qt.quit() }
      }
    }
  }
}
'''.replace('WIDTH', str(args.width)).replace('HEIGHT', str(args.height)).replace('FIXTURE', fixture).replace('OUTPUT', output))
        environment = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), DCONF_BACKEND='memory',
                           QT_QPA_PLATFORM='offscreen', OMARCHY_YUBIKEY_LANGUAGE=args.language,
                           OMARCHY_LANGUAGE_FILE=str(directory / 'absent-language'))
        environment.pop('WAYLAND_DISPLAY', None)
        result = subprocess.run(['qs', '-p', str(directory / 'shell.qml'), '--no-color'],
                                env=environment, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        bad = ('UI_TESTS_FAILED', ' ERROR', 'ReferenceError', 'TypeError', 'Binding loop', 'Failed to load')
        if result.returncode or 'UI_TESTS_PASSED' not in output or any(value in output for value in bad):
            print(output)
            return 1
        print(f'Native UI passed: keyboard cancellation/confirmation, action arguments, all five pages; {args.width}×{args.height}, {args.language}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
