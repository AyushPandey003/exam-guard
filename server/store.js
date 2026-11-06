// SQLite storage (Node 22+ built-in `node:sqlite`). Swap this module to move to Postgres.
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

function open(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS sessions (
      nonce TEXT PRIMARY KEY, key TEXT NOT NULL,
      last_seq INTEGER NOT NULL DEFAULT -1, last_seen INTEGER NOT NULL,
      locked INTEGER NOT NULL DEFAULT 0, reasons TEXT NOT NULL DEFAULT '[]',
      review TEXT, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, nonce TEXT NOT NULL,
      ts INTEGER NOT NULL, seq INTEGER NOT NULL, violations TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS events_nonce ON events(nonce);
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS staff_tokens (
      token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL
    );
  `);

  const q = {
    insSession: db.prepare('INSERT INTO sessions (nonce,key,last_seen,created_at) VALUES (?,?,?,?)'),
    getSession: db.prepare('SELECT * FROM sessions WHERE nonce = ?'),
    saveSession: db.prepare('UPDATE sessions SET last_seq=?, last_seen=?, locked=?, reasons=?, review=? WHERE nonce=?'),
    activeSessions: db.prepare('SELECT * FROM sessions WHERE locked = 0'),
    allSessions: db.prepare('SELECT * FROM sessions ORDER BY locked DESC, created_at DESC LIMIT 500'),
    insEvent: db.prepare('INSERT INTO events (nonce,ts,seq,violations) VALUES (?,?,?,?)'),
    lastEvents: db.prepare('SELECT ts,seq,violations FROM events WHERE nonce=? ORDER BY id DESC LIMIT 20'),
    insUser: db.prepare('INSERT OR REPLACE INTO users (username,salt,hash,created_at) VALUES (?,?,?,?)'),
    getUser: db.prepare('SELECT * FROM users WHERE username = ?'),
    insToken: db.prepare('INSERT INTO staff_tokens (token_hash,username,expires_at) VALUES (?,?,?)'),
    getToken: db.prepare('SELECT * FROM staff_tokens WHERE token_hash = ?'),
    delToken: db.prepare('DELETE FROM staff_tokens WHERE token_hash = ?'),
    purgeTokens: db.prepare('DELETE FROM staff_tokens WHERE expires_at < ?'),
  };

  const hydrate = (r) => r && ({
    nonce: r.nonce, key: r.key, lastSeq: r.last_seq, lastSeen: r.last_seen,
    locked: !!r.locked, reasons: JSON.parse(r.reasons), review: r.review ? JSON.parse(r.review) : null,
    createdAt: r.created_at,
  });

  return {
    createSession(nonce, key) { q.insSession.run(nonce, key, Date.now(), Date.now()); },
    getSession: (nonce) => hydrate(q.getSession.get(nonce)),
    saveSession(s) {
      q.saveSession.run(s.lastSeq, s.lastSeen, s.locked ? 1 : 0, JSON.stringify(s.reasons),
        s.review ? JSON.stringify(s.review) : null, s.nonce);
    },
    activeSessions: () => q.activeSessions.all().map(hydrate),
    listSessions() {
      return q.allSessions.all().map(hydrate).map((s) => ({
        ...s, key: undefined,
        events: q.lastEvents.all(s.nonce).reverse().map((e) => ({ ts: e.ts, seq: e.seq, violations: JSON.parse(e.violations) })),
      }));
    },
    addEvent: (nonce, ts, seq, violations) => q.insEvent.run(nonce, ts, seq, JSON.stringify(violations)),

    // ---- staff accounts: scrypt password hashes, opaque bearer tokens stored hashed ----
    setUser(username, password) {
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.scryptSync(password, salt, 64).toString('hex');
      q.insUser.run(username, salt, hash, Date.now());
    },
    verifyUser(username, password) {
      const u = q.getUser.get(username);
      // Hash even for unknown users so response time doesn't reveal which usernames exist.
      const salt = u ? u.salt : '00'.repeat(16);
      const got = crypto.scryptSync(password, salt, 64);
      return !!u && crypto.timingSafeEqual(got, Buffer.from(u.hash, 'hex'));
    },
    createToken(username, ttlMs) {
      const token = crypto.randomBytes(32).toString('hex');
      q.purgeTokens.run(Date.now());
      q.insToken.run(sha(token), username, Date.now() + ttlMs);
      return token;
    },
    tokenUser(token) {
      const t = token && q.getToken.get(sha(token));
      return t && t.expires_at > Date.now() ? t.username : null;
    },
    revokeToken: (token) => q.delToken.run(sha(token)),
  };
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
module.exports = { open };
