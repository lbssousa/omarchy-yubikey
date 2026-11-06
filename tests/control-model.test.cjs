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
test('OpenPGP status keeps only its flags and a non-identifying key summary', () => {
  const result = model.cleanSnapshot({schema:1,ok:true,openpgp:{card:true,imported:'true',linked:true,trusted:false,fingerprint:'private-value',key:{algorithm:'ed25519'}}});
  assert.deepEqual(result.openpgp, {card:true,imported:false,linked:true,trusted:false,key:null});
  assert.equal(JSON.stringify(result).includes('private-value'), false);
  assert.deepEqual(model.cleanSnapshot({schema:1,ok:true}).openpgp, {card:false,imported:false,linked:false,trusted:false,key:null});
  const key = {algorithm:'ed25519',sign:true,encrypt:'yes',authenticate:true,expires:'2030-01-01',expired:false,uids:7,uid:'private-value'};
  assert.deepEqual(model.cleanSnapshot({schema:1,ok:true,openpgp:{card:true,imported:true,key:key}}).openpgp.key,
    {algorithm:'ed25519',expires:'2030-01-01',expired:false,uids:7,sign:true,encrypt:false,authenticate:true});
  const hostile = model.cleanSnapshot({schema:1,ok:true,openpgp:{card:true,imported:true,key:{algorithm:'private-value',expires:'private-value',uids:-3}}});
  assert.deepEqual([hostile.openpgp.key.algorithm, hostile.openpgp.key.expires, hostile.openpgp.key.uids], ['other','',0]);
  assert.deepEqual(model.parameters('openpgp-import','',''), []);
});
