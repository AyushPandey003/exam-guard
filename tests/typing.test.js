// No dependencies: node tests/typing.test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const typing = require('../ui/typing.js');

assert.deepEqual(typing.metrics('', 'hello', 0), { characters: 0, wpm: 0, accuracy: 100, seconds: 0 });
assert.equal(typing.metrics('hello', 'hello', 60000).wpm, 1);
assert.equal(typing.metrics('hello', 'hello', 1000).wpm, 60);
assert.equal(typing.metrics('hxllo', 'hello', 60000).accuracy, 80);
assert.equal(typing.metrics('hello!', 'hello', 60000).accuracy, 83);
assert.equal(typing.metrics('😀', '😀', 1000).characters, 1);
assert.match(typing.diagnosticSummary({ supported: false }), /not supported/);
const clean = { supported: true, keyboard_active: true, mouse_active: true, injected_keys: 0, injected_clicks: 0, samples: 39, mean_ms: 100, sd_ms: 0 };
assert.match(typing.diagnosticSummary(clean), /Collecting/);
assert.match(typing.diagnosticSummary({ ...clean, samples: 40 }), /INPUT_TIMING/);
assert.doesNotMatch(typing.diagnosticSummary({ ...clean, samples: 40, sd_ms: 4 }), /INPUT_TIMING/);
assert.doesNotMatch(typing.diagnosticSummary({ ...clean, samples: 40, mean_ms: 250 }), /INPUT_TIMING/);
assert.match(typing.diagnosticSummary({ ...clean, injected_keys: 3 }), /INJECTED_INPUT/);
assert.match(typing.diagnosticSummary({ ...clean, injected_clicks: 3 }), /INJECTED_INPUT/);
assert.match(typing.diagnosticSummary({ ...clean, keyboard_active: false }), /incomplete/);

const elements = new Map();
const element = () => ({ textContent: '', className: '', value: '', disabled: false, children: [],
  appendChild(child) { this.children.push(child); }, addEventListener(type, fn) { this[type] = fn; }, focus() {} });
const document = { getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); }, createElement: element };
let now = 1000;
const commands = [];
const context = vm.createContext({ document, performance: { now: () => now }, setInterval() {}, setTimeout() {},
  window: { TypingTest: typing, __TAURI__: {
    core: { invoke: async name => { commands.push(name); if (name === 'input_diagnostics') return clean; throw new Error('Server offline'); } },
    event: { listen: async () => () => {} },
  } },
});
const html = fs.readFileSync(require.resolve('../ui/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
vm.runInContext(script, context);
function update(seq, status, error = null, violations = []) {
  context.update = { nonce: 'test-session', report: { payload: JSON.stringify({ seq, violations }) }, status, error };
  vm.runInContext('render(update)', context);
}
update(0, { locked: false, reasons: [] });
assert.equal(elements.get('status').className, 'good');
update(1, { locked: true, reasons: ['heartbeat lost'] });
update(0, { locked: false, reasons: [] });
assert.equal(elements.get('status').className, 'bad', 'stale report must not unlock');
update(2, null, 'Server offline');
assert.match(elements.get('status').textContent, /Exam locked.*Server offline/);
update(3, { locked: true, reasons: [] }, null, [{ code: 'TEST', detail: '<img onerror=alert(1)>' }]);
assert.equal(elements.get('status').children.at(-1).children[0].textContent, 'TEST: <img onerror=alert(1)>');

elements.get('typing-reset').onclick();
const input = elements.get('typing-input');
input.value = 'hello'; input.input();
now += 1000;
vm.runInContext('refreshMetrics()', context);
assert.equal(elements.get('wpm').textContent, 60);
elements.get('typing-stop').onclick();
assert.equal(input.disabled, true);
now += 5000;
vm.runInContext('refreshMetrics()', context);
assert.equal(elements.get('wpm').textContent, 60, 'finished time must stay frozen');
elements.get('typing-reset').onclick();
assert.equal(input.value, '');
assert.equal(elements.get('wpm').textContent, 0);
assert.equal(elements.get('status').className, 'bad', 'practice reset cannot unlock server session');
input.value = typing.passage; input.input();
assert.equal(input.disabled, true, 'exact passage auto-finishes');
assert.match(elements.get('typing-state').textContent, /completed/);
assert.ok(!commands.includes('start_session'), 'practice must not start monitoring');

(async () => {
  await elements.get('go').onclick();
  assert.equal(elements.get('go').disabled, false, 'failed start allows retry');
  assert.match(elements.get('status').textContent, /Server offline/);
  console.log('Typing metrics, diagnostic thresholds, practice controls and server-state UI checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
