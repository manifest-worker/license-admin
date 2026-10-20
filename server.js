'use strict';
/**
 * License Admin Panel - server (zero dependencies, Node 18+)
 *  - Admin UI + API (login required)
 *  - Public validation API for your software:  POST /api/validate
 *
 * Config (env vars, all optional):
 *   PORT=3000
 *   ADMIN_USER=admin
 *   ADMIN_PASSWORD=...   (if omitted, a random one is generated on first run and printed)
 *   DATA_DIR=./data
 *   COOKIE_SECURE=1      (set when serving over HTTPS)
 *   TRUST_PROXY=1        (set when behind nginx/Cloudflare so client IPs are read from X-Forwarded-For)
 *   SIGNING_KEY_PEM=...  ECDSA P-256 PRIVATE key (PEM). Signs /api/validate answers for the app.
 *   CONTENT_KEY_B64=...  base64 of 32 random bytes; released only to valid licenses (asset decryption).
 *   REQUIRE_SIGNED=1     reject old unsigned clients (set once all users updated to the new app)
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_FILE = path.join(DATA_DIR, 'licenses.json');
const CFG_FILE = path.join(DATA_DIR, 'admin.json');
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const SESSION_TTL = 1000 * 60 * 60 * 12; // 12h
const DAY = 86400000;

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ------------------------- response signing (app) ------------------------- */
const REQUIRE_SIGNED = process.env.REQUIRE_SIGNED === '1';
let SIGNING_KEY = null;
try {
  const pem = (process.env.SIGNING_KEY_PEM || '').replace(/\\n/g, '\n');
  if (pem) SIGNING_KEY = crypto.createPrivateKey(pem);
} catch (_) { console.error('SIGNING_KEY_PEM is set but invalid'); }
const CONTENT_KEY_B64 = (Buffer.from(process.env.CONTENT_KEY_B64 || '', 'base64').length === 32)
  ? process.env.CONTENT_KEY_B64 : '';
if (!SIGNING_KEY) console.warn('WARNING: SIGNING_KEY_PEM missing/invalid - signed validation disabled');
if (!CONTENT_KEY_B64) console.warn('WARNING: CONTENT_KEY_B64 missing/invalid (needs base64 of 32 bytes)');

/** Sends a validation answer. Signed envelope when the app sent a nonce, legacy JSON otherwise. */
function vjson(res, status, obj, cors, ctx) {
  if (!ctx.signed) return json(res, status, obj, cors);
  const out = { ...obj, deviceId: ctx.deviceId, nonce: ctx.nonce, iat: Date.now() };
  if (obj.valid === true) out.ck = CONTENT_KEY_B64; // key only ever leaves for a valid license
  const payload = JSON.stringify(out);
  const sig = crypto.sign('sha256', Buffer.from(payload, 'utf8'), SIGNING_KEY).toString('base64');
  return json(res, status, { payload, sig }, cors);
}

/* ---------------------------- admin credentials --------------------------- */
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function loadAdmin() {
  const envUser = process.env.ADMIN_USER || 'admin';
  const envPass = process.env.ADMIN_PASSWORD;
  let cfg = null;
  try { cfg = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8')); } catch (_) {}

  if (envPass) {
    const salt = crypto.randomBytes(16).toString('hex');
    cfg = { user: envUser, salt, hash: hashPassword(envPass, salt) };
    fs.writeFileSync(CFG_FILE, JSON.stringify(cfg), { mode: 0o600 });
  } else if (!cfg) {
    const pass = crypto.randomBytes(9).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    cfg = { user: envUser, salt, hash: hashPassword(pass, salt) };
    fs.writeFileSync(CFG_FILE, JSON.stringify(cfg), { mode: 0o600 });
    console.log('\n==============================================');
    console.log(' First run - admin account created');
    console.log('   username: ' + envUser);
    console.log('   password: ' + pass);
    console.log(' Save this now. Set ADMIN_PASSWORD to change it.');
    console.log('==============================================\n');
  }
  return cfg;
}
const admin = loadAdmin();

/* --------------------------------- storage -------------------------------- */
let db = { licenses: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (_) {}
if (!Array.isArray(db.licenses)) db.licenses = [];

let saving = false, dirty = false;
function save() {
  if (saving) { dirty = true; return; }
  saving = true;
  const tmp = DB_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db, null, 2), (err) => {
    if (!err) fs.rename(tmp, DB_FILE, () => done());
    else done();
  });
  function done() { saving = false; if (dirty) { dirty = false; save(); } }
}

/* -------------------------------- helpers --------------------------------- */
function genKey() {
  const groups = [];
  for (let i = 0; i < 5; i++) groups.push(String(crypto.randomInt(0, 10000)).padStart(4, '0'));
  return groups.join('-');
}
function uniqueKey() {
  for (let i = 0; i < 50; i++) {
    const k = genKey();
    if (!db.licenses.some((l) => l.key === k)) return k;
  }
  throw new Error('Could not generate unique key');
}
function statusOf(l, now = Date.now()) {
  if (l.expiresAt == null) return 'unused';
  return now > l.expiresAt ? 'expired' : 'active';
}
function publicView(l) {
  return {
    id: l.id, key: l.key, note: l.note || '', createdAt: l.createdAt,
    durationDays: l.durationDays, startOnFirstUse: l.startOnFirstUse,
    expiresAt: l.expiresAt, maxDevices: l.maxDevices,
    devices: l.devices, status: statusOf(l),
  };
}
function intIn(v, min, max) {
  const n = Number(v);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}
const safeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

/* ---------------------------- sessions / limits --------------------------- */
const sessions = new Map(); // token -> expiresAt
const buckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [t, e] of sessions) if (e < now) sessions.delete(t);
  for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
}, 60000).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}
/** returns true if allowed */
function rateLimit(req, res, name, max, windowMs) {
  const id = name + ':' + clientIp(req);
  const now = Date.now();
  let b = buckets.get(id);
  if (!b || b.reset < now) { b = { n: 0, reset: now + windowMs }; buckets.set(id, b); }
  if (++b.n > max) {
    json(res, 429, { error: 'Too many attempts. Try again later.' }, { 'Retry-After': Math.ceil((b.reset - now) / 1000) });
    return false;
  }
  return true;
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch (_) {} }
  });
  return out;
}
function isAuthed(req) {
  const t = parseCookies(req).sid;
  const exp = t && sessions.get(t);
  return !!exp && exp > Date.now();
}

/* ------------------------------ http plumbing ----------------------------- */
const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};
function json(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { ...BASE_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(body);
}
function readBody(req, limit = 50 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('Body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (_) { reject(Object.assign(new Error('Invalid JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  let file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) file = path.join(PUBLIC_DIR, 'index.html');
  fs.readFile(file, (err, data) => {
    if (err) {
      // SPA fallback
      return fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, d2) => {
        if (e2) { res.writeHead(404, BASE_HEADERS); return res.end('Not found'); }
        res.writeHead(200, { ...BASE_HEADERS, 'Content-Type': MIME['.html'] });
        res.end(d2);
      });
    }
    res.writeHead(200, { ...BASE_HEADERS, 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

/* --------------------------------- routes --------------------------------- */
async function handleApi(req, res, pathname) {
  const method = req.method;

  /* ---- public validation endpoint (for your software) ----
   * POST /api/validate  { "key": "0000-...", "deviceId": "unique-device-id" }
   * -> { valid: true, expiresAt, daysLeft, devicesUsed, maxDevices }
   * -> { valid: false, reason: "not_found|expired|device_limit|bad_request" }
   */
  if (pathname === '/api/validate') {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (method === 'OPTIONS') { res.writeHead(204, { ...BASE_HEADERS, ...cors }); return res.end(); }
    if (method !== 'POST') return json(res, 405, { error: 'Use POST' }, cors);
    if (!rateLimit(req, res, 'validate', 60, 60 * 1000)) return;
    const b = await readBody(req);
    const key = String(b.key || '').trim();
    const deviceId = String(b.deviceId || '').trim().slice(0, 200);

    // Signed mode: the app sends a random nonce; we echo it (plus deviceId) inside a signed payload.
    const nonce = typeof b.nonce === 'string' ? b.nonce : '';
    const rawDevice = typeof b.deviceId === 'string' ? b.deviceId : '';
    const signed = nonce !== '';
    if (signed && !(SIGNING_KEY && CONTENT_KEY_B64)) return json(res, 503, { valid: false, reason: 'server_not_configured' }, cors);
    if (!signed && REQUIRE_SIGNED) return json(res, 400, { valid: false, reason: 'bad_request' }, cors);
    if (signed && (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || rawDevice.length > 200))
      return json(res, 400, { valid: false, reason: 'bad_request' }, cors);
    const ctx = { signed, nonce, deviceId: rawDevice };
    const reply = (status, obj) => vjson(res, status, obj, cors, ctx);

    if (!key || !deviceId) return reply(400, { valid: false, reason: 'bad_request' });

    const l = db.licenses.find((x) => x.key.toLowerCase() === key.toLowerCase());
    if (!l) return reply(200, { valid: false, reason: 'not_found' });

    const now = Date.now();
    if (l.expiresAt != null && now > l.expiresAt) return reply(200, { valid: false, reason: 'expired' });

    let dev = l.devices.find((d) => d.id === deviceId);
    if (!dev) {
      if (l.devices.length >= l.maxDevices) return reply(200, { valid: false, reason: 'device_limit' });
      dev = { id: deviceId, firstSeen: now, lastSeen: now };
      l.devices.push(dev);
    }
    dev.lastSeen = now;
    if (l.expiresAt == null) l.expiresAt = now + l.durationDays * DAY; // start on first use
    save();
    return reply(200, {
      valid: true, expiresAt: l.expiresAt,
      daysLeft: Math.max(0, Math.ceil((l.expiresAt - now) / DAY)),
      devicesUsed: l.devices.length, maxDevices: l.maxDevices,
    });
  }

  // CSRF defence in depth: reject cross-site state-changing admin requests
  if (method !== 'GET') {
    const origin = req.headers.origin;
    if (origin) {
      let host = ''; try { host = new URL(origin).host; } catch (_) {}
      if (host !== req.headers.host) return json(res, 403, { error: 'Bad origin' });
    }
  }

  /* ---- auth ---- */
  if (pathname === '/api/login' && method === 'POST') {
    if (!rateLimit(req, res, 'login', 8, 15 * 60 * 1000)) return;
    const { username, password } = await readBody(req);
    const okUser = safeEq(String(username || ''), admin.user);
    const okPass = safeEq(hashPassword(String(password || ''), admin.salt), admin.hash);
    if (!(okUser && okPass)) return json(res, 401, { error: 'Invalid username or password' });
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_TTL);
    return json(res, 200, { ok: true }, {
      'Set-Cookie': `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${COOKIE_SECURE ? '; Secure' : ''}`,
    });
  }
  if (pathname === '/api/logout' && method === 'POST') {
    const t = parseCookies(req).sid;
    if (t) sessions.delete(t);
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  /* ---- everything below requires login ---- */
  if (!isAuthed(req)) return json(res, 401, { error: 'Not logged in' });

  if (pathname === '/api/me' && method === 'GET') return json(res, 200, { user: admin.user });

  if (pathname === '/api/licenses' && method === 'GET') {
    return json(res, 200, { licenses: db.licenses.map(publicView).sort((a, b) => b.createdAt - a.createdAt) });
  }

  if (pathname === '/api/licenses' && method === 'POST') {
    const b = await readBody(req);
    const days = intIn(b.days, 1, 3650);
    const maxDevices = intIn(b.maxDevices, 1, 10000);
    const quantity = intIn(b.quantity ?? 1, 1, 500);
    if (!days) return json(res, 400, { error: 'Duration must be 1-3650 days' });
    if (!maxDevices) return json(res, 400, { error: 'Max devices must be 1-10000' });
    if (!quantity) return json(res, 400, { error: 'Quantity must be 1-500' });

    const custom = typeof b.customKey === 'string' ? b.customKey.trim() : '';
    if (custom) {
      if (!/^[A-Za-z0-9_-]{4,64}$/.test(custom))
        return json(res, 400, { error: 'Custom key: 4-64 chars, letters, numbers, - and _ only' });
      if (db.licenses.some((l) => l.key.toLowerCase() === custom.toLowerCase()))
        return json(res, 409, { error: 'That key already exists' });
    }
    const note = String(b.note || '').slice(0, 200);
    const startOnFirstUse = !!b.startOnFirstUse;
    const now = Date.now();
    const made = [];
    const count = custom ? 1 : quantity;
    for (let i = 0; i < count; i++) {
      const lic = {
        id: crypto.randomUUID(), key: custom || uniqueKey(), note, createdAt: now,
        durationDays: days, startOnFirstUse,
        expiresAt: startOnFirstUse ? null : now + days * DAY,
        maxDevices, devices: [],
      };
      db.licenses.push(lic); made.push(lic);
    }
    save();
    return json(res, 200, { licenses: made.map(publicView) });
  }

  const m = pathname.match(/^\/api\/licenses\/([0-9a-f-]{36})(\/extend)?$/);
  if (m) {
    const idx = db.licenses.findIndex((x) => x.id === m[1]);
    if (idx < 0) return json(res, 404, { error: 'Not found' });
    const l = db.licenses[idx];

    if (m[2] && method === 'POST') { // extend
      const b = await readBody(req);
      const days = intIn(b.days, 1, 3650);
      if (!days) return json(res, 400, { error: 'Days must be 1-3650' });
      if (l.expiresAt == null) l.durationDays += days; // timer not started yet
      else l.expiresAt = Math.max(l.expiresAt, Date.now()) + days * DAY;
      save();
      return json(res, 200, { license: publicView(l) });
    }
    if (!m[2] && method === 'PATCH') {
      const b = await readBody(req);
      if (b.maxDevices !== undefined) {
        const n = intIn(b.maxDevices, 1, 10000);
        if (!n) return json(res, 400, { error: 'Max devices must be 1-10000' });
        l.maxDevices = n;
      }
      if (b.resetDevices) l.devices = [];
      if (b.note !== undefined) l.note = String(b.note).slice(0, 200);
      save();
      return json(res, 200, { license: publicView(l) });
    }
    if (!m[2] && method === 'DELETE') {
      db.licenses.splice(idx, 1);
      save();
      return json(res, 200, { ok: true });
    }
  }

  return json(res, 404, { error: 'Not found' });
}

const server = http.createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url, 'http://x').pathname;
    if (pathname.startsWith('/api/')) return await handleApi(req, res, pathname);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, BASE_HEADERS); return res.end(); }
    serveStatic(req, res, decodeURIComponent(pathname));
  } catch (err) {
    if (!res.headersSent) json(res, err.status || 500, { error: err.status ? err.message : 'Server error' });
    if (!err.status) console.error(err);
  }
});
server.listen(PORT, () => console.log(`License admin running on http://localhost:${PORT}`));
