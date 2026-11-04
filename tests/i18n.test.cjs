const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const model = require('../plugins/yubikey.polkit/PolkitModel.js');
const locale = require('../plugins/yubikey.polkit/Locale.js');
const root = path.join(__dirname, '..');
const registry = JSON.parse(fs.readFileSync(path.join(root, 'i18n/locales.json')));

test('all shell locale aliases agree with the CLI', () => {
  for (const [input, expected] of [['de_AT.UTF-8', 'de'], ['pt_BR', 'pt-BR'], ['es_ES', 'es-MX'],
    ['nb_NO', 'no'], ['tl_PH', 'fil'], ['zh_HK', 'zh-TW'], ['../../de', 'en']]) {
    assert.equal(locale.normalize(input, registry), expected);
  }
  assert.deepEqual(locale.parse('broken JSON'), {});
});

test('translated labels insert untrusted text once without markup interpretation', () => {
  const tr = (source, values) => locale.render(source, values);
  const text = "Authentication is required to run 'tool %2 <b>&' as the super user";
  assert.equal(model.authorizationLabel(text, tr), "Authorize running 'tool %2 <b>&'");
  assert.equal(locale.render('%2 / %1 / %10', ['label %2', '<b>&</b>']), '<b>&</b> / label %2 / %10');
  assert.equal(model.responseLabel('Account-specific password prompt:', tr), 'Account-specific password prompt:');
});

test('every translated fallback prompt is recognized without treating PIN or password prompts as choices', () => {
  const choices = JSON.parse(fs.readFileSync(path.join(root, 'plugins/yubikey.polkit/i18n/fallback-prompts.json')));
  assert.equal(choices.length, 50);
  for (const prompt of choices) assert.equal(model.isFallbackPrompt(prompt, choices), true);
  for (const prompt of ['Password:', 'Enter PIN:', 'password', 'Use password fallback?', '<b>Use password</b>'])
    assert.equal(model.isFallbackPrompt(prompt, choices), false);
});
