'use strict';
/*
 * JLPL (O&M) Portal server
 * Zero external dependencies. Needs Node.js 22.5 or later (uses built-in node:sqlite).
 * Run:  node server.js        Configure with environment variables (see README.md).
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
process.removeAllListeners('warning'); // hide the "SQLite is experimental" notice
const { DatabaseSync } = require('node:sqlite');

const VERSION = '1.0.0';
const PORT = +process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PUBLIC_DIR = path.join(__dirname, 'public');
const AUTH_MODE = (process.env.AUTH_MODE || 'local').toLowerCase();          // local | header
const AUTH_HEADER = (process.env.AUTH_HEADER || 'x-remote-user').toLowerCase();
const ADMIN_USERS = (process.env.ADMIN_USERS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const SESSION_HOURS = +process.env.SESSION_HOURS || 12;
const MAX_UPLOAD_MB = +process.env.MAX_UPLOAD_MB || 15;

const ROLES = ['admin', 'station', 'fs', 'hr', 'security', 'viewer'];
const ALL = 'all';
/* Who may read (r), create (c), update (u) and delete (d) each collection.
   'owner' lets the person who created a record change it. Admin can always do everything. */
const PERMS = {
  events:      { r: ALL, c: ['hr', 'fs', 'station'], u: ['hr', 'fs', 'owner'], d: ['owner'] },
  contracts:   { r: ['security', 'hr', 'station'], c: ['security'], u: ['security'], d: [] },
  employees:   { r: ['security', 'hr'], c: ['security'], u: ['security'], d: [] },
  trips:       { r: ALL, c: ALL, u: ALL, d: ['owner'] },
  pm_done:     { r: ALL, c: ['station'], u: ['station'], d: ['owner'] },
  checklist:   { r: ALL, c: ['station'], u: ['station'], d: [] },
  equipment:   { r: ALL, c: ['station'], u: ['station'], d: ['owner'] },
  incidents:   { r: ALL, c: ALL, u: ['fs', 'owner'], d: [] },
  permits:     { r: ALL, c: ['fs', 'station'], u: ['fs', 'station'], d: [] },
  patrol:      { r: ALL, c: ['station', 'security'], u: ['owner', 'station'], d: ['owner'] },
  integrity:   { r: ALL, c: ['station'], u: ['station'], d: ['owner'] },
  certs:       { r: ['fs', 'hr', 'station', 'security'], c: ['fs', 'hr'], u: ['fs', 'hr'], d: ['fs', 'hr'] },
  spares:      { r: ALL, c: ['station'], u: ['station'], d: ['owner'] },
  shiftlog:    { r: ALL, c: ['station'], u: ['owner'], d: [] },
  documents:   { r: ALL, c: ['hr', 'fs', 'station'], u: ['owner'], d: ['owner'] },
  directory:   { r: ALL, c: ['hr'], u: ['hr'], d: ['hr'] },
  trainings:   { r: ALL, c: ['fs', 'hr'], u: ['fs', 'hr'], d: ['fs', 'hr'] },
  nominations: { r: ALL, c: ALL, u: ['owner'], d: ['owner', 'fs', 'hr'] },
  calibration: { r: ALL, c: ['station'], u: ['station'], d: ['owner'] }
};
const SETTINGS_PERMS = { notices: ['hr', 'fs'], quicklinks: [], safety: ['fs'], contacts: ['station'], org: ['hr'] };
const FILE_TYPES = {
  'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp',
  'text/plain': '.txt', 'text/csv': '.csv',
  'application/msword': '.doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.ms-excel': '.xls', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/vnd.ms-powerpoint': '.ppt', 'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx'
};

/* ---------- database ---------- */
fs.mkdirSync(path.join(DATA_DIR, 'uploads'), { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'jlpl.db'));
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT, role TEXT NOT NULL DEFAULT 'viewer',
  station TEXT, pass TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, collection TEXT NOT NULL, data TEXT NOT NULL, station TEXT,
  created_by INTEGER, created_at TEXT, updated_by INTEGER, updated_at TEXT);
CREATE INDEX IF NOT EXISTS rec_col ON records(collection, station);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, username TEXT, action TEXT, target TEXT, detail TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT, type TEXT, size INTEGER, created_by INTEGER, created_at TEXT);
`);
const now = () => new Date().toISOString();

/* ---------- passwords ---------- */
function hashPass(p) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(p, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + h.toString('hex');
}
function checkPass(p, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const [, s, h] = stored.split('$');
  const got = crypto.scryptSync(String(p), Buffer.from(s, 'hex'), 64);
  const want = Buffer.from(h, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
const strongEnough = p => typeof p === 'string' && p.length >= 10 && /[A-Za-z]/.test(p) && /\d/.test(p);

if (AUTH_MODE === 'local' && !db.prepare('SELECT COUNT(*) n FROM users').get().n) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url') + '7';
  db.prepare('INSERT INTO users(username,name,role,pass,created_at) VALUES(?,?,?,?,?)').run('admin', 'Portal administrator', 'admin', hashPass(pw), now());
  console.log('\n  First run: created user "admin" with password: ' + pw + '\n  Sign in and change it from the user menu.\n');
}

/* ---------- helpers ---------- */
function audit(user, action, target, detail, req) {
  db.prepare('INSERT INTO audit(ts,user_id,username,action,target,detail,ip) VALUES(?,?,?,?,?,?,?)')
    .run(now(), user ? user.id : null, user ? user.username : null, action, target || '', detail ? String(detail).slice(0, 500) : '', ip(req));
}
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const pubUser = u => u && ({ id: u.id, username: u.username, name: u.name, role: u.role, station: u.station, active: !!u.active });
function allowed(user, rule, rec) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (rule === ALL) return true;
  if (!Array.isArray(rule)) return false;
  if (rule.includes(user.role)) return true;
  return rule.includes('owner') && rec && rec.created_by === user.id;
}
function permsFor(user) {
  const out = {};
  for (const [c, p] of Object.entries(PERMS)) out[c] = { r: allowed(user, p.r), c: allowed(user, p.c), u: allowed(user, p.u), d: allowed(user, p.d), own: { u: (p.u || []).includes?.('owner'), d: (p.d || []).includes?.('owner') } };
  out._settings = Object.fromEntries(Object.entries(SETTINGS_PERMS).map(([k, r]) => [k, allowed(user, r)]));
  return out;
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(token, userId, Date.now() + SESSION_HOURS * 3600e3);
  res.setHeader('Set-Cookie', `jlpl_sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}${COOKIE_SECURE ? '; Secure' : ''}`);
}
function currentUser(req) {
  if (AUTH_MODE === 'header') {
    let name = String(req.headers[AUTH_HEADER] || '').trim();
    if (!name) return null;
    name = name.replace(/^.*\\/, '').replace(/@.*$/, '').toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(name)) return null;
    let u = db.prepare('SELECT * FROM users WHERE username=?').get(name);
    if (!u) {
      db.prepare('INSERT INTO users(username,name,role,created_at) VALUES(?,?,?,?)').run(name, name, ADMIN_USERS.includes(name) ? 'admin' : 'viewer', now());
      u = db.prepare('SELECT * FROM users WHERE username=?').get(name);
    }
    return u.active ? u : null;
  }
  const t = cookies(req).jlpl_sid;
  if (!t) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(t);
  if (!s || s.expires < Date.now()) { if (s) db.prepare('DELETE FROM sessions WHERE token=?').run(t); return null; }
  db.prepare('UPDATE sessions SET expires=? WHERE token=?').run(Date.now() + SESSION_HOURS * 3600e3, t);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);
  return u && u.active ? u : null;
}
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('Request too large'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
      catch { reject(Object.assign(new Error('Invalid JSON'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}
function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw Object.assign(new Error('Record must be an object'), { code: 400 });
  const out = {};
  for (const [k, v] of Object.entries(d)) {
    if (k.startsWith('_') || k === 'id' || !/^[A-Za-z0-9]{1,40}$/.test(k)) continue;
    out[k] = v;
  }
  const s = JSON.stringify(out);
  if (s.length > 100000) throw Object.assign(new Error('Record too large'), { code: 413 });
  return out;
}
function recOut(r) {
  const d = JSON.parse(r.data);
  return { ...d, id: r.id, _by: r.created_by, _byName: r.by_name || '', _at: r.created_at, _upd: r.updated_at };
}
const loginHits = new Map();
function rateLimited(key) {
  const t = Date.now(), e = loginHits.get(key) || { n: 0, reset: t + 15 * 60e3 };
  if (t > e.reset) { e.n = 0; e.reset = t + 15 * 60e3; }
  e.n++; loginHits.set(key, e);
  return e.n > 10;
}
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()), 3600e3).unref();

/* ---------- API ---------- */
async function api(req, res, url) {
  const p = url.pathname.replace(/^\/api/, '');
  const m = req.method;
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'jlpl') return send(res, 403, { error: 'Missing request header' });

  if (p === '/health') return send(res, 200, { ok: true, app: 'jlpl', version: VERSION, authMode: AUTH_MODE });

  if (p === '/login' && m === 'POST') {
    if (AUTH_MODE !== 'local') return send(res, 400, { error: 'Sign-in is handled by the network' });
    if (rateLimited(ip(req))) return send(res, 429, { error: 'Too many attempts. Try again in 15 minutes.' });
    const b = await readBody(req, 10e3);
    const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(b.username || '').toLowerCase().trim());
    if (!u || !u.active || !checkPass(b.password || '', u.pass)) { audit(null, 'login-failed', String(b.username || '').slice(0, 64), '', req); return send(res, 401, { error: 'Wrong username or password.' }); }
    setSession(res, u.id); audit(u, 'login', '', '', req);
    return send(res, 200, { user: pubUser(u), perms: permsFor(u) });
  }
  const user = currentUser(req);
  if (p === '/logout' && m === 'POST') {
    const t = cookies(req).jlpl_sid; if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
    res.setHeader('Set-Cookie', 'jlpl_sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
    if (user) audit(user, 'logout', '', '', req);
    return send(res, 200, { ok: true });
  }
  if (!user) return send(res, 401, { error: 'Please sign in.' });
  if (p === '/me') return send(res, 200, { user: pubUser(user), perms: permsFor(user), authMode: AUTH_MODE });

  if (p === '/password' && m === 'POST') {
    if (AUTH_MODE !== 'local') return send(res, 400, { error: 'Passwords are managed by the network' });
    const b = await readBody(req, 10e3);
    if (!checkPass(b.old || '', user.pass)) return send(res, 400, { error: 'Current password is wrong.' });
    if (!strongEnough(b.new)) return send(res, 400, { error: 'Use at least 10 characters with letters and numbers.' });
    db.prepare('UPDATE users SET pass=? WHERE id=?').run(hashPass(b.new), user.id);
    audit(user, 'password-change', user.username, '', req);
    return send(res, 200, { ok: true });
  }

  // collections
  let mm = p.match(/^\/c\/([a-z_]+)(?:\/(\d+))?$/);
  if (mm) {
    const [, col, idStr] = mm; const perm = PERMS[col];
    if (!perm) return send(res, 404, { error: 'Unknown collection' });
    const id = idStr ? +idStr : null;
    if (m === 'GET' && !id) {
      if (!allowed(user, perm.r)) return send(res, 403, { error: 'Not allowed' });
      const st = url.searchParams.get('station');
      const rows = st
        ? db.prepare('SELECT r.*, u.name by_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.collection=? AND r.station=? ORDER BY r.id DESC LIMIT 5000').all(col, st)
        : db.prepare('SELECT r.*, u.name by_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.collection=? ORDER BY r.id DESC LIMIT 5000').all(col);
      return send(res, 200, rows.map(recOut));
    }
    if (m === 'POST' && !id) {
      if (!allowed(user, perm.c)) return send(res, 403, { error: 'Your role cannot add records here.' });
      const d = cleanData(await readBody(req, 300e3));
      const r = db.prepare('INSERT INTO records(collection,data,station,created_by,created_at) VALUES(?,?,?,?,?)').run(col, JSON.stringify(d), typeof d.station === 'string' ? d.station : null, user.id, now());
      audit(user, 'create', col + '/' + r.lastInsertRowid, summarize(d), req);
      const row = db.prepare('SELECT r.*, u.name by_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.id=?').get(r.lastInsertRowid);
      return send(res, 201, recOut(row));
    }
    if (!id) return send(res, 405, { error: 'Method not allowed' });
    const rec = db.prepare('SELECT * FROM records WHERE id=? AND collection=?').get(id, col);
    if (!rec) return send(res, 404, { error: 'Not found' });
    if (m === 'PUT') {
      if (!allowed(user, perm.u, rec)) return send(res, 403, { error: 'Your role cannot change this record.' });
      const d = cleanData(await readBody(req, 300e3));
      db.prepare('UPDATE records SET data=?, station=?, updated_by=?, updated_at=? WHERE id=?').run(JSON.stringify(d), typeof d.station === 'string' ? d.station : null, user.id, now(), id);
      audit(user, 'update', col + '/' + id, summarize(d), req);
      const row = db.prepare('SELECT r.*, u.name by_name FROM records r LEFT JOIN users u ON u.id=r.created_by WHERE r.id=?').get(id);
      return send(res, 200, recOut(row));
    }
    if (m === 'DELETE') {
      if (!allowed(user, perm.d, rec)) return send(res, 403, { error: 'Your role cannot delete this record.' });
      db.prepare('DELETE FROM records WHERE id=?').run(id);
      audit(user, 'delete', col + '/' + id, rec.data, req);
      return send(res, 200, { ok: true });
    }
    return send(res, 405, { error: 'Method not allowed' });
  }

  // settings
  mm = p.match(/^\/settings(?:\/([a-z]+))?$/);
  if (mm) {
    const key = mm[1];
    if (m === 'GET' && !key) {
      const o = {}; db.prepare('SELECT key,value FROM settings').all().forEach(r => { o[r.key] = JSON.parse(r.value); });
      return send(res, 200, o);
    }
    if (m === 'PUT' && key) {
      if (!(key in SETTINGS_PERMS)) return send(res, 404, { error: 'Unknown setting' });
      if (!allowed(user, SETTINGS_PERMS[key])) return send(res, 403, { error: 'Your role cannot change this setting.' });
      const b = await readBody(req, 200e3);
      const v = JSON.stringify(b.value ?? null);
      db.prepare('INSERT INTO settings(key,value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at').run(key, v, user.id, now());
      audit(user, 'settings', key, v, req);
      return send(res, 200, { ok: true });
    }
    return send(res, 405, { error: 'Method not allowed' });
  }

  // files
  if (p === '/files' && m === 'POST') {
    if (user.role === 'viewer' && !allowed(user, PERMS.incidents.c)) return send(res, 403, { error: 'Not allowed' });
    const b = await readBody(req, MAX_UPLOAD_MB * 1.4e6 + 10e3);
    const type = String(b.type || '');
    if (!FILE_TYPES[type]) return send(res, 415, { error: 'This file type is not allowed. Use PDF, image, Office or text files.' });
    const buf = Buffer.from(String(b.data || ''), 'base64');
    if (!buf.length) return send(res, 400, { error: 'Empty file' });
    if (buf.length > MAX_UPLOAD_MB * 1e6) return send(res, 413, { error: `Files must be under ${MAX_UPLOAD_MB} MB.` });
    const id = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(path.join(DATA_DIR, 'uploads', id), buf);
    const name = String(b.name || 'file').replace(/[^\w.\- ()]+/g, '_').slice(0, 120);
    db.prepare('INSERT INTO files(id,name,type,size,created_by,created_at) VALUES(?,?,?,?,?,?)').run(id, name, type, buf.length, user.id, now());
    audit(user, 'upload', id, name, req);
    return send(res, 201, { id, name, type, size: buf.length });
  }
  mm = p.match(/^\/files\/([a-f0-9]{32})$/);
  if (mm && m === 'GET') {
    const f = db.prepare('SELECT * FROM files WHERE id=?').get(mm[1]);
    if (!f) return send(res, 404, { error: 'Not found' });
    const inline = /^(application\/pdf|image\/)/.test(f.type);
    res.writeHead(200, { 'Content-Type': f.type, 'Content-Length': f.size, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, max-age=3600',
      'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${f.name.replace(/"/g, '')}"` });
    return fs.createReadStream(path.join(DATA_DIR, 'uploads', f.id)).pipe(res);
  }

  // users (admin)
  if (p.startsWith('/users')) {
    if (user.role !== 'admin') return send(res, 403, { error: 'Administrators only' });
    if (p === '/users' && m === 'GET') return send(res, 200, db.prepare('SELECT * FROM users ORDER BY username').all().map(pubUser));
    if (p === '/users' && m === 'POST') {
      const b = await readBody(req, 10e3);
      const username = String(b.username || '').toLowerCase().trim();
      if (!/^[a-z0-9._-]{2,64}$/.test(username)) return send(res, 400, { error: 'Username may use letters, numbers, dot, dash and underscore.' });
      if (!ROLES.includes(b.role)) return send(res, 400, { error: 'Unknown role' });
      if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return send(res, 400, { error: 'That username already exists.' });
      if (AUTH_MODE === 'local' && !strongEnough(b.password)) return send(res, 400, { error: 'Initial password needs at least 10 characters with letters and numbers.' });
      db.prepare('INSERT INTO users(username,name,role,station,pass,created_at) VALUES(?,?,?,?,?,?)').run(username, String(b.name || username).slice(0, 80), b.role, b.station || null, AUTH_MODE === 'local' ? hashPass(b.password) : null, now());
      audit(user, 'user-create', username, b.role, req);
      return send(res, 201, { ok: true });
    }
    mm = p.match(/^\/users\/(\d+)(\/password)?$/);
    if (mm) {
      const target = db.prepare('SELECT * FROM users WHERE id=?').get(+mm[1]);
      if (!target) return send(res, 404, { error: 'Not found' });
      const b = await readBody(req, 10e3);
      if (mm[2] && m === 'POST') {
        if (!strongEnough(b.password)) return send(res, 400, { error: 'Use at least 10 characters with letters and numbers.' });
        db.prepare('UPDATE users SET pass=? WHERE id=?').run(hashPass(b.password), target.id);
        db.prepare('DELETE FROM sessions WHERE user_id=?').run(target.id);
        audit(user, 'password-reset', target.username, '', req);
        return send(res, 200, { ok: true });
      }
      if (m === 'PUT') {
        if (b.role && !ROLES.includes(b.role)) return send(res, 400, { error: 'Unknown role' });
        if (target.id === user.id && (b.role && b.role !== 'admin' || b.active === false)) return send(res, 400, { error: 'You cannot remove your own admin access.' });
        db.prepare('UPDATE users SET name=?, role=?, station=?, active=? WHERE id=?').run(String(b.name ?? target.name).slice(0, 80), b.role || target.role, b.station ?? target.station, b.active === false ? 0 : 1, target.id);
        if (b.active === false) db.prepare('DELETE FROM sessions WHERE user_id=?').run(target.id);
        audit(user, 'user-update', target.username, JSON.stringify({ role: b.role, active: b.active, station: b.station }), req);
        return send(res, 200, { ok: true });
      }
    }
    return send(res, 405, { error: 'Method not allowed' });
  }
  if (p === '/audit' && m === 'GET') {
    if (user.role !== 'admin') return send(res, 403, { error: 'Administrators only' });
    const lim = Math.min(2000, +url.searchParams.get('limit') || 300);
    return send(res, 200, db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(lim));
  }
  return send(res, 404, { error: 'Not found' });
}
function summarize(d) { return Object.entries(d).filter(([, v]) => typeof v !== 'object').slice(0, 6).map(([k, v]) => k + '=' + String(v).slice(0, 40)).join('; '); }

/* ---------- static files ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8' };
function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    const ext = path.extname(file);
    res.writeHead(200, { 'Content-Type': TYPES[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' || rel === '/sw.js' ? 'no-cache' : 'public, max-age=3600' });
    fs.createReadStream(file).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    serveStatic(req, res, url);
  } catch (e) {
    if (!e.code || typeof e.code !== 'number') console.error(e);
    if (!res.headersSent) send(res, typeof e.code === 'number' ? e.code : 500, { error: typeof e.code === 'number' ? e.message : 'Server error' });
  }
});
if (AUTH_MODE === 'header' && !['127.0.0.1', '::1', 'localhost'].includes(HOST)) console.warn('WARNING: AUTH_MODE=header trusts the ' + AUTH_HEADER + ' header. Set HOST=127.0.0.1 so only your reverse proxy can reach the portal.');
server.listen(PORT, HOST, () => console.log(`JLPL portal ${VERSION} on http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}  (auth: ${AUTH_MODE}, data: ${DATA_DIR})`));
