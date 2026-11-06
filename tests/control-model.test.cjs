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
test('OpenPGP keeps bounded public identity and per-slot state without card serials', () => {
  const key = {algorithm:'ed25519', fingerprint:'A'.repeat(40), uid:'<b>Public</b>\u202e'+'x'.repeat(300),
    sign:true, encrypt:'yes', authenticate:false, revoked:true, serial:'private-value'};
  const value = model.cleanSnapshot({schema:1,ok:true,openpgp:{card:true,imported:true,ready:false,
    key:key,slots:{sign:{present:true,location:'disk',ready:false,serial:'private-value'}}}}).openpgp;
  assert.equal(value.key.fingerprint, 'A'.repeat(40));
  assert.equal(value.key.uid.length,256);
  assert.equal(value.key.uid.includes('\u202e'),false);
  assert.equal(value.key.encrypt,false);
  assert.equal(value.key.revoked,true);
  assert.equal(value.slots.sign.location,'disk');
  assert.equal(JSON.stringify(value).includes('private-value'),false);
  assert.equal(model.cleanSnapshot({schema:1,ok:true,openpgp:{imported:true,key:{fingerprint:'bad'}}}).openpgp.key.fingerprint,'');
  assert.deepEqual(model.parameters('openpgp-import','',''),[]);
});
test('SSH exposes public metadata but removal requires an exact stable key reference', () => {
  const id = 'a'.repeat(64), fingerprint = 'SHA256:'+'A'.repeat(43);
  const source = {schema:1,ok:true,ssh:{count:2,keys:[
    {id:id,type:'ed25519-sk',application:'ssh:github.com',fingerprint:fingerprint,passphrase:true,host:true,name:'private-value'},
    {id:'1',name:'private-value'},null]}};
  const value = model.cleanSnapshot(source).ssh;
  assert.equal(value.keys.length,1);
  assert.equal(value.keys[0].application,'ssh:github.com');
  assert.equal(value.keys[0].fingerprint,fingerprint);
  assert.equal(JSON.stringify(value).includes('private-value'),false);
  assert.equal(model.cleanSnapshot({schema:1,ok:true,ssh:{keys:new Array(80).fill({id:id})}}).ssh.keys.length,50);
  assert.deepEqual(model.parameters('ssh-remove','','',id),['--key-id',id]);
  for (const id of [undefined,0,1,51,'1 --x','02','A'.repeat(64)]) assert.equal(model.parameters('ssh-remove','','',id),null);
  assert.deepEqual(model.parameters('ssh-import','',''),[]);
});
