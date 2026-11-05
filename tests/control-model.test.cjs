const {test} = require('node:test');
const assert = require('node:assert/strict');
const model = require('../ui/ControlModel.js');
test('the window accepts status metadata and discards arbitrary secret fields', () => {
  const result = model.cleanSnapshot({schema:1,ok:true,supported:true,connected:1,enrollment:{count:2,credential:'private-value'},keyring:{count:2,ciphertext:'private-value',label:'private-value'},operation:{action:'setup',phase:'running',ticket:'private-value'},serial:'private-value'});
  assert.equal(result.enrollment.count, 2);
  assert.equal(result.operation.action, 'setup');
  assert.equal(JSON.stringify(result).includes('private-value'), false);
  assert.equal(model.cleanSnapshot({schema:2,ok:true}), null);
});
test('actions use validated arguments and reject injected paths', () => {
  assert.deepEqual(model.parameters('luks-enroll','/dev/disk/by-id/example',''), ['--device','/dev/disk/by-id/example']);
  for (const path of ['/dev/../etc/example','/dev/example;echo','$(echo example)','/dev/example\n--flag']) assert.equal(model.parameters('luks-check',path,''),null);
  assert.equal(model.parameters('__proto__','',''),null);
  assert.equal(model.parameters('rollback','','../../example'),null);
  assert.deepEqual(model.parameters('rollback','','20261104-120000-abcdef01'), ['--backup','20261104-120000-abcdef01']);
});
test('untrusted status cannot enable operations or inject text', () => {
  const value = model.cleanSnapshot({schema:1,ok:true,supported:'true',connected:Infinity,enrollment:{count:-4},sudo:{state:'private-value'},operation:{action:'__proto__',phase:'private-value'}});
  assert.equal(value.supported,false);
  assert.equal(value.enrollment.count,0);
  assert.equal(value.sudo.state,'not-configured');
  assert.deepEqual(value.operation,{action:'',phase:''});
});
test('SSH status keeps only a bounded count', () => {
  assert.deepEqual(model.cleanSnapshot({schema:1,ok:true,ssh:{count:2,names:['private-value']}}).ssh, {count:2});
  assert.deepEqual(model.cleanSnapshot({schema:1,ok:true,ssh:{count:-1}}).ssh, {count:0});
  assert.deepEqual(model.parameters('ssh-import','',''), []);
});
