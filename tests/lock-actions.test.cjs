const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const actions = require('../plugins/yubikey.lock/LockActions.js');

test('only actions the probe reports as true are offered', () => {
  assert.deepEqual(actions.available(actions.parseCapabilities('{"suspend":true,"reboot":"yes","powerOff":true}')).map(a => a.id), ['suspend', 'powerOff']);
  for (const text of ['', 'not json', '[true]', 'null', '{"suspend":1}'])
    assert.deepEqual(actions.available(actions.parseCapabilities(text)), [], text);
});

test('F keys map to offered actions and commands are fixed', () => {
  const offered = actions.available({suspend: true, reboot: true});
  assert.equal(actions.forFKey(offered, 1).id, 'suspend');
  assert.equal(actions.forFKey(offered, 3).id, 'reboot');
  assert.equal(actions.forFKey(offered, 4), null);
  assert.equal(actions.forFKey(null, 1), null);
  assert.deepEqual(actions.command({id: 'powerOff'}), ['systemctl', 'poweroff']);
  assert.deepEqual(actions.command({id: 'suspend', verb: 'isolate rescue.target'}), ['systemctl', 'suspend']);
  assert.equal(actions.command({id: '__proto__'}), null);
  assert.equal(actions.command(null), null);
  assert.deepEqual(actions.actions.filter(a => a.confirm).map(a => a.id), ['reboot', 'powerOff']);
});

// Exercise the actual QML service functions without creating a session lock.
function service(offered) {
  const source = fs.readFileSync(require.resolve('../plugins/yubikey.lock/Service.qml'), 'utf8');
  const events = [];
  const context = {
    LockActions: actions, lockRequested: true, authenticatingPassword: false,
    lockActions: actions.available(offered), pendingLockAction: null,
    enteredPassword: 'synthetic-password', failureMessage: 'synthetic-failure',
    logEvent: () => {}, runWake: () => events.push('wake'),
    lockActionTimeout: {restart: () => events.push('timeout-start'), stop: () => events.push('timeout-stop')},
    lockActionProc: {running: false, command: null},
  };
  Object.defineProperty(context.lockActionProc, 'running', {
    get() { return this._running || false },
    set(value) { if (value) events.push(['run', this.command]); this._running = value },
  });
  context.root = context;
  vm.createContext(context);
  for (const name of ['requestLockAction', 'cancelLockAction', 'runLockAction']) {
    const code = source.match(new RegExp(`  function ${name}\\([^]*?\\n  }`));
    assert.ok(code, `missing service function ${name}`);
    vm.runInContext(code[0].trim(), context);
  }
  return {context, events};
}

test('suspend runs at once and clears the typed text', () => {
  const {context, events} = service({suspend: true});
  context.requestLockAction(actions.forFKey(context.lockActions, 1));
  assert.deepEqual(events.filter(e => Array.isArray(e)), [['run', ['systemctl', 'suspend']]]);
  assert.equal(context.enteredPassword, '');
  assert.equal(context.failureMessage, '');
});

test('reboot asks first, and runs only once confirmed', () => {
  const {context, events} = service({reboot: true});
  context.requestLockAction(actions.forFKey(context.lockActions, 3));
  assert.equal(context.pendingLockAction.id, 'reboot');
  assert.equal(events.some(e => Array.isArray(e)), false);
  context.runLockAction(context.pendingLockAction);
  assert.equal(context.pendingLockAction, null);
  assert.deepEqual(events.filter(e => Array.isArray(e)), [['run', ['systemctl', 'reboot']]]);
});

test('cancelling, an unlocked session, a password check or an unoffered action run nothing', () => {
  let {context, events} = service({reboot: true});
  context.requestLockAction(context.lockActions[0]);
  context.cancelLockAction();
  assert.equal(context.pendingLockAction, null);
  ({context, events} = service({suspend: true}));
  context.authenticatingPassword = true;
  context.requestLockAction(context.lockActions[0]);
  context.authenticatingPassword = false;
  context.lockRequested = false;
  context.requestLockAction(context.lockActions[0]);
  context.runLockAction(context.lockActions[0]);
  context.lockRequested = true;
  context.runLockAction(actions.actions[2]);
  assert.equal(events.some(e => Array.isArray(e)), false);
});
