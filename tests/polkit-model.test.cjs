const {test} = require('node:test');
const assert = require('node:assert/strict');
const model = require('../plugins/yubikey.polkit/PolkitModel.js');

test('PAM discovery ignores comments and non-auth stacks', () => {
  const raw = '# auth sufficient pam_u2f.so\naccount required pam_u2f.so\n';
  assert.equal(model.fido2ConfiguredFromPamConfig(raw), false);
  assert.equal(model.fingerprintConfiguredFromPamConfig('# auth sufficient pam_fprintd.so'), false);
});

test('key and fingerprint can appear behind a preceding auth gate', () => {
  const raw = 'auth optional pam_exec.so\nauth sufficient pam_u2f.so cue\nauth sufficient pam_fprintd.so\n';
  assert.equal(model.fido2ConfiguredFromPamConfig(raw), true);
  assert.equal(model.fingerprintConfiguredFromPamConfig(raw), true);
});

test('ordinary password stack has neither device prompt', () => {
  assert.equal(model.fido2ConfiguredFromPamConfig('auth include system-auth'), false);
  assert.equal(model.fingerprintConfiguredFromPamConfig('auth include system-auth'), false);
  assert.equal(model.fido2ConfiguredFromPamConfig(null), false);
});

test('authorization message shortens a command while preserving unfamiliar text', () => {
  assert.equal(model.authorizationLabel("Authentication is required to run 'example-command' as the super user"), "Authorize running 'example-command'");
  assert.equal(model.authorizationLabel('Custom authorization request'), 'Custom authorization request');
  assert.equal(model.promptLooksFingerprint('Swipe your finger'), true);
  assert.equal(model.promptLooksFingerprint('Password:'), false);
});

test('explicit fallback is recognized independently of PIN/password responses', () => {
  assert.equal(model.isFallbackPrompt('Use password fallback? Type password to continue: '), true);
  assert.equal(model.isFallbackPrompt('Password:'), false);
  assert.equal(model.isFallbackPrompt('Enter PIN for key:'), false);
  assert.equal(model.responseLabel('Enter PIN for key: '), 'Enter PIN for key:');
  assert.equal(model.responseLabel('Account password:'), 'Account password:');
});
