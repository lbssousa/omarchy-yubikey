const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

// Exercise the actual QML service functions without creating a session lock.
function service() {
  const source = fs.readFileSync(require.resolve('../plugins/yubikey.lock/Service.qml'), 'utf8');
  const events = [];
  const context = {
    lockRequested: true, authMethod: 'key', authenticatingPassword: false,
    fido2Configured: true, fingerprintConfigured: true, fido2Authenticating: true,
    enteredPassword: '', failureMessage: '', failedAttempts: 0, pendingPassword: '',
    keyResponseRequired: true, sessionLock: {secure: true},
    PamResult: {Success: 0, Failed: 1},
    Qt: {callLater: fn => fn()},
    logEvent: () => {}, runWake: () => {}, finishUnlock: () => events.push('unlock'),
    fingerprintRetryTimer: {stop: () => {}, restart: () => events.push('fingerprint-retry')},
    fido2Pam: {active: true, respond: s => events.push(['key-response', s]), abort: () => events.push('key-abort')},
    passwordPam: {active: false, responseRequired: true, start: () => { events.push('password-start'); context.passwordPam.active = true; return true; }, respond: s => events.push(['password-response', s]), abort: () => {}},
    fingerprintPam: {active: false, abort: () => {}, start: () => true},
  };
  context.root = context;
  vm.createContext(context);
  for (const name of ['resetAuthenticationState', 'submitPassword', 'respondToPasswordPrompt',
    'chooseMethod', 'startFido2', 'startFingerprint', 'handleFido2Finished', 'handleFingerprintFinished', 'handlePasswordFailure']) {
    const code = source.match(new RegExp(`  function ${name}\\([^]*?\\n  }`));
    assert.ok(code, `missing service function ${name}`);
    vm.runInContext(code[0].trim(), context);
  }
  return {context, events};
}

test('PIN responses only reach the key conversation and are cleared', () => {
  const {context, events} = service();
  context.enteredPassword = 'synthetic-pin';
  context.submitPassword(context.enteredPassword);
  assert.deepEqual(events, [['key-response', 'synthetic-pin']]);
  assert.equal(context.enteredPassword, '');
  assert.equal(context.pendingPassword, '');
});

test('key failure stays on key method without starting password or retrying PIN', () => {
  const {context, events} = service();
  context.handleFido2Finished(context.PamResult.Failed);
  assert.equal(context.authMethod, 'key');
  assert.match(context.failureMessage, /failed/);
  assert.deepEqual(events, []);
});

test('explicit method change aborts key; a late key success cannot unlock', () => {
  const {context, events} = service();
  context.chooseMethod('password');
  context.handleFido2Finished(context.PamResult.Success);
  assert.equal(context.authMethod, 'password');
  assert.deepEqual(events, ['key-abort']);
  context.submitPassword('synthetic-password');
  assert.deepEqual(events.slice(-2), ['password-start', ['password-response', 'synthetic-password']]);
  assert.equal(context.pendingPassword, '');
});

test('background fingerprint success cannot unlock the selected key method', () => {
  const {context, events} = service();
  context.handleFingerprintFinished(context.PamResult.Success);
  assert.deepEqual(events, []);
});
