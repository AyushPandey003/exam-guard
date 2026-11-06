// ExamGuard verifier. Node 22+, no npm dependencies: `node verify.js`
// Hot path (seq/lastSeen) is cached in memory and flushed every few seconds;
// locks, events, reviews and logins are written to SQLite immediately.
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const { open } = require('./store');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || __dirname + '/examguard.db';
const AUDIT_LOG = process.env.AUDIT_LOG || __dirname + '/audit.jsonl';
const MIN_AGENT_VERSION = process.env.MIN_AGENT_VERSION || '0.1.0';
const MAX_SKEW_S = 10;              // reject stale/replayed timestamps
const HEARTBEAT_TIMEOUT_MS = 8000;  // 2s heartbeat; 4 missed = agent killed
const STAFF_TOKEN_TTL_MS = 8 * 3600e3;
const LOGIN_MAX_FAILS = 5, LOGIN_WINDOW_MS = 15 * 60e3;

const store = open(DB_PATH);
const cache = new Map(); // nonce -> session object (write-through for locks/reviews)
const dirty = new Set();

// Restart grace: sessions that were live get a fresh lastSeen so a server restart
// doesn't mass-lock everyone before agents can reconnect.
for (const s of store.activeSessions()) { s.lastSeen = Date.now(); cache.set(s.nonce, s); }

function audit(entry) {
  try { fs.appendFileSync(AUDIT_LOG, JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n'); } catch {}
}
function getSession(nonce) {
  let s = cache.get(nonce);
  if (!s) { s = store.getSession(nonce); if (s) cache.set(nonce, s); }
  return s;
}
function versionLt(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y; }
  return false;
}

function issueSession() {
  const nonce = crypto.randomUUID(), key = crypto.randomBytes(32).toString('hex');
  store.createSession(nonce, key);
  cache.set(nonce, { nonce, key, lastSeq: -1, lastSeen: Date.now(), locked: false, reasons: [], review: null });
  return { key, nonce };
}

function lock(s, why) {
  if (s.locked) return;
  s.locked = true; s.reasons.push(why);
  store.saveSession(s); audit({ type: 'lock', nonce: s.nonce, why });
}

function handleReport({ payload, sig }) {
  const p = JSON.parse(payload);
  const s = getSession(p.nonce);
  if (!s) return { error: 'unknown session' };

  const expect = crypto.createHmac('sha256', s.key).update(payload).digest();
  const got = Buffer.from(String(sig), 'hex');
  if (got.length !== expect.length || !crypto.timingSafeEqual(got, expect)) { lock(s, 'bad signature'); return { locked: true }; }
  if (!p.agent_version || versionLt(p.agent_version, MIN_AGENT_VERSION)) {
    lock(s, `agent outdated (${p.agent_version || 'unknown'} < ${MIN_AGENT_VERSION})`); return { locked: true };
  }
  if (p.seq <= s.lastSeq) { lock(s, 'replayed/out-of-order seq'); return { locked: true }; }
  if (Math.abs(Date.now() / 1000 - p.ts) > MAX_SKEW_S) { lock(s, 'stale timestamp'); return { locked: true }; }

  s.lastSeq = p.seq; s.lastSeen = Date.now(); dirty.add(s.nonce);
  if (!p.ok) {
    store.addEvent(s.nonce, p.ts, p.seq, p.violations);
    lock(s, p.violations.map((v) => v.code).join(','));
  }
  return { locked: s.locked, reasons: s.reasons };
}

setInterval(() => { // flush hot-path state
  for (const n of dirty) { const s = cache.get(n); if (s) store.saveSession(s); }
  dirty.clear();
}, 5000).unref();

setInterval(() => { // watchdog: no heartbeat => agent killed or network cut => lock
  for (const s of cache.values())
    if (!s.locked && Date.now() - s.lastSeen > HEARTBEAT_TIMEOUT_MS) lock(s, 'heartbeat lost');
}, 2000).unref();

// ---- staff auth with per-IP login throttling ----
const fails = new Map(); // ip -> [timestamps]
function throttled(ip) {
  const a = (fails.get(ip) || []).filter((t) => Date.now() - t < LOGIN_WINDOW_MS);
  fails.set(ip, a); return a.length >= LOGIN_MAX_FAILS;
}
const bearer = (req) => (req.headers.authorization || '').replace(/^Bearer /, '');
const staffUser = (req) => store.tokenUser(bearer(req));

const server = http.createServer((req, res) => {
  const chunks = []; let size = 0;
  req.on('data', (c) => { size += c.length; if (size > 64 * 1024) req.destroy(); else chunks.push(c); });
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    const send = (o, code = 200) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
    const json = () => { try { return JSON.parse(body || '{}'); } catch { return {}; } };
    const url = req.url.split('?')[0];

    try {
      // ---- agent / exam page ----
      if (url === '/api/guard/session' && req.method === 'POST') return send(issueSession());
      if (url === '/api/guard/report' && req.method === 'POST') return send(handleReport(json()));
      let m = url.match(/^\/api\/guard\/status\/([\w-]+)$/);
      if (m) { const s = getSession(m[1]); return send(s ? { locked: s.locked, reasons: s.reasons } : { error: 'unknown' }, s ? 200 : 404); }

      // ---- staff ----
      if (url === '/dashboard') { res.setHeader('content-type', 'text/html'); return res.end(fs.readFileSync(__dirname + '/dashboard.html')); }
      if (url === '/api/auth/login' && req.method === 'POST') {
        const ip = req.socket.remoteAddress;
        if (throttled(ip)) return send({ error: 'too many attempts, try later' }, 429);
        const { username, password } = json();
        if (!username || !password || !store.verifyUser(String(username), String(password))) {
          fails.get(ip).push(Date.now()); audit({ type: 'login_fail', username: String(username || ''), ip });
          return send({ error: 'invalid credentials' }, 401);
        }
        audit({ type: 'login', username, ip });
        return send({ token: store.createToken(username, STAFF_TOKEN_TTL_MS) });
      }
      if (url === '/api/auth/logout' && req.method === 'POST') { store.revokeToken(bearer(req)); return send({ ok: true }); }

      const user = staffUser(req);
      if (url === '/api/guard/sessions') {
        if (!user) return send({ error: 'unauthorized' }, 401);
        for (const n of dirty) { const s = cache.get(n); if (s) store.saveSession(s); } dirty.clear();
        return send(store.listSessions());
      }
      m = url.match(/^\/api\/guard\/review\/([\w-]+)$/);
      if (m && req.method === 'POST') {
        if (!user) return send({ error: 'unauthorized' }, 401);
        const s = getSession(m[1]);
        if (!s) return send({ error: 'unknown' }, 404);
        const { decision, note } = json();
        if (!['cleared', 'confirmed'].includes(decision)) return send({ error: 'bad decision' }, 400);
        if (!note || !String(note).trim()) return send({ error: 'note required' }, 400);
        s.review = { decision, note: String(note), by: user, at: Date.now() };
        if (decision === 'cleared') { s.locked = false; s.lastSeen = Date.now(); } // reviewer overrides a false positive
        store.saveSession(s); audit({ type: 'review', nonce: s.nonce, decision, note: s.review.note, by: user });
        return send({ ok: true });
      }
      send({ error: 'not found' }, 404);
    } catch (e) { send({ error: 'bad request' }, 400); }
  });
});

// Local test setup: do not expose unauthenticated session issuance to the LAN.
if (require.main === module) server.listen(PORT, '127.0.0.1', () => console.log(`verifier on http://127.0.0.1:${PORT} (db: ${DB_PATH})`));
module.exports = { server, store };
