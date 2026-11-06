// Smoke test: `node test.js` (uses a temp DB, listens on :3055)
const os = require('os'), fs = require('fs'), path = require('path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'examguard-'));
process.env.DB_PATH = dir + '/t.db';
process.env.AUDIT_LOG = dir + '/audit.jsonl';
process.env.MIN_AGENT_VERSION = '0.1.0';

const crypto = require('crypto');
const assert = require('assert');
const { server, store } = require('./verify.js');
const B = 'http://localhost:3055';

const post = (p, body, headers = {}) =>
  fetch(B + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })
    .then(async (r) => ({ status: r.status, ...(await r.json()) }));

function report(sess, seq, { ok = true, violations = [], version = '0.1.0', tsOffset = 0 } = {}) {
  const payload = JSON.stringify({ agent_version: version, nonce: sess.nonce, seq,
    ts: Math.floor(Date.now() / 1000) + tsOffset, ok, violations });
  return post('/api/guard/report', { payload, sig: crypto.createHmac('sha256', sess.key).update(payload).digest('hex') });
}
const status = (n) => fetch(`${B}/api/guard/status/${n}`).then((r) => r.json());
const fresh = () => post('/api/guard/session', {});

(async () => {
  await new Promise((r) => server.listen(3055, r));
  store.setUser('alice', 'correct horse battery');

  let s = await fresh();
  assert.equal((await report(s, 0)).locked, false, 'clean report stays unlocked');
  assert.equal((await report(s, 0)).locked, true, 'replayed seq locks');

  s = await fresh();
  const bad = JSON.stringify({ agent_version: '0.1.0', nonce: s.nonce, seq: 0, ts: Math.floor(Date.now() / 1000), ok: true, violations: [] });
  assert.equal((await post('/api/guard/report', { payload: bad, sig: 'ab'.repeat(32) })).locked, true, 'bad signature locks');

  s = await fresh(); assert.equal((await report(s, 0, { version: '0.0.9' })).locked, true, 'old agent locks');
  s = await fresh(); assert.equal((await report(s, 0, { tsOffset: -60 })).locked, true, 'stale timestamp locks');

  // violation -> lock -> staff login -> review
  const v = await fresh();
  assert.equal((await report(v, 0, { ok: false, violations: [{ code: 'VM_PROCESS', detail: 'vmtoolsd' }] })).locked, true, 'violation locks');

  assert.equal((await fetch(B + '/api/guard/sessions')).status, 401, 'no token rejected');
  assert.equal((await fetch(B + '/api/guard/sessions', { headers: { Authorization: 'Bearer nope' } })).status, 401, 'bad token rejected');
  assert.equal((await post('/api/auth/login', { username: 'alice', password: 'wrong' })).status, 401, 'wrong password rejected');
  const { token } = await post('/api/auth/login', { username: 'alice', password: 'correct horse battery' });
  assert.ok(token, 'login returns token');
  const A = { Authorization: 'Bearer ' + token };

  const list = await (await fetch(B + '/api/guard/sessions', { headers: A })).json();
  const row = list.find((x) => x.nonce === v.nonce);
  assert.equal(row.events[0].violations[0].code, 'VM_PROCESS', 'events stored');
  assert.equal(row.key, undefined, 'session key never exposed to dashboard');

  assert.equal((await post(`/api/guard/review/${v.nonce}`, { decision: 'cleared' }, A)).status, 400, 'review requires note');
  assert.equal((await post(`/api/guard/review/${v.nonce}`, { decision: 'cleared', note: 'false positive' }, A)).ok, true);
  assert.equal((await status(v.nonce)).locked, false, 'clear unlocks');
  assert.equal(store.getSession(v.nonce).review.by, 'alice', 'reviewer recorded in DB');

  await post('/api/auth/logout', {}, A);
  assert.equal((await fetch(B + '/api/guard/sessions', { headers: A })).status, 401, 'token revoked after logout');

  // login throttling
  let last;
  for (let i = 0; i < 6; i++) last = await post('/api/auth/login', { username: 'alice', password: 'x' });
  assert.equal(last.status, 429, 'login throttled after repeated failures');

  // persistence: lock state survives reading straight from the DB
  const persisted = store.getSession(v.nonce);
  assert.equal(persisted.locked, false);
  s = await fresh(); await report(s, 0, { ok: false, violations: [{ code: 'REMOTE_TOOL', detail: 'anydesk' }] });
  assert.equal(store.getSession(s.nonce).locked, true, 'lock persisted to SQLite');

  // heartbeat loss
  s = await fresh(); await report(s, 0);
  await new Promise((r) => setTimeout(r, 11000));
  assert.equal((await status(s.nonce)).locked, true, 'lost heartbeat locks');

  console.log('all server checks passed');
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
