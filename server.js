require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const required = ['IMAGEKIT_PUBLIC_KEY', 'IMAGEKIT_PRIVATE_KEY', 'SESSION_SECRET', 'ADMIN_PASSWORD'];
const missing = required.filter(k => !process.env[k] || process.env[k].startsWith('replace_with_') || process.env[k].includes('xxxxxxxx'));
if (missing.length) {
  console.error(`Missing or placeholder environment variables: ${missing.join(', ')}. Copy .env.example to .env and configure it.`);
  process.exit(1);
}
if (process.env.ADMIN_PASSWORD.length < 12) {
  console.error('ADMIN_PASSWORD must be at least 12 characters.');
  process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'", 'https://upload.imagekit.io', 'https://api.imagekit.io'],
  objectSrc: ["'none'"], upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
}}}));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'portal.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS links (
 id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
 code_hash TEXT NOT NULL, employee_hint TEXT NOT NULL DEFAULT '', expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS uploads (
 id INTEGER PRIMARY KEY AUTOINCREMENT, link_id INTEGER NOT NULL REFERENCES links(id), employee_name TEXT NOT NULL,
 original_name TEXT NOT NULL, file_id TEXT, url TEXT, file_path TEXT, mime_type TEXT, size_bytes INTEGER NOT NULL DEFAULT 0,
 uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, status TEXT NOT NULL DEFAULT 'uploaded'
);
CREATE INDEX IF NOT EXISTS idx_uploads_employee ON uploads(employee_name);
CREATE INDEX IF NOT EXISTS idx_uploads_link ON uploads(link_id);
`);

app.use(session({
 name: 'sohansoft.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
 store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, table: 'sessions' }),
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
const uploadAuthLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const adminOnly = (req, res, next) => req.session && req.session.isAdmin ? next() : res.status(401).json({ error: 'Admin login required.' });
const clean = (s, max = 180) => String(s || '').trim().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);
const randomToken = () => crypto.randomBytes(24).toString('base64url');
const imagekitBase = ('/' + (process.env.IMAGEKIT_BASE_FOLDER || '/SohanSoftEmployeeUploads').split('/').filter(Boolean).join('/')).replace(/\/$/, '');

function getLink(token) {
 return db.prepare('SELECT * FROM links WHERE token = ?').get(token);
}
function activeLink(link) {
 return !!link && !link.revoked && (!link.expires_at || new Date(link.expires_at).getTime() > Date.now());
}
function imageKitAuth() {
 const token = crypto.randomUUID();
 const expire = Math.floor(Date.now() / 1000) + 10 * 60;
 const signature = crypto.createHmac('sha1', process.env.IMAGEKIT_PRIVATE_KEY).update(token + expire).digest('hex');
 return { token, expire, signature, publicKey: process.env.IMAGEKIT_PUBLIC_KEY };
}
async function imagekitRequest(url, options = {}) {
 const auth = Buffer.from(process.env.IMAGEKIT_PRIVATE_KEY + ':').toString('base64');
 const response = await fetch(url, { ...options, headers: { Authorization: `Basic ${auth}`, ...(options.headers || {}) } });
 const body = await response.text();
 let data; try { data = body ? JSON.parse(body) : {}; } catch { data = { message: body }; }
 if (!response.ok) throw new Error(data.message || `ImageKit API returned ${response.status}`);
 return data;
}

app.get('/', (_req, res) => res.redirect('/admin'));
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'SohanSoft Employee Upload Portal' }));
app.post('/api/admin/login', loginLimiter, async (req, res) => {
 const username = clean(req.body.username, 100); const password = String(req.body.password || '');
 const expectedUser = process.env.ADMIN_USERNAME || 'admin';
 const okUser = username.length === expectedUser.length && crypto.timingSafeEqual(Buffer.from(username), Buffer.from(expectedUser));
 // Password comparison is constant-time for a fixed-length derived digest.
 const supplied = crypto.createHash('sha256').update(password).digest();
 const expected = crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD).digest();
 if (!okUser || !crypto.timingSafeEqual(supplied, expected)) return res.status(401).json({ error: 'Incorrect username or password.' });
 req.session.regenerate(err => {
  if (err) return res.status(500).json({ error: 'Could not create session.' });
  req.session.isAdmin = true;
  req.session.save(err2 => err2 ? res.status(500).json({ error: 'Could not save session.' }) : res.json({ ok: true }));
 });
});
app.post('/api/admin/logout', adminOnly, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/me', (req, res) => res.json({ authenticated: !!(req.session && req.session.isAdmin) }));

app.get('/api/admin/links', adminOnly, (_req, res) => {
 const links = db.prepare(`SELECT l.id,l.token,l.label,l.employee_hint,l.expires_at,l.revoked,l.created_at,
 (SELECT COUNT(*) FROM uploads u WHERE u.link_id=l.id) AS upload_count,
 (SELECT COALESCE(SUM(size_bytes),0) FROM uploads u WHERE u.link_id=l.id) AS total_bytes
 FROM links l ORDER BY l.id DESC`).all();
 res.json({ links });
});
app.post('/api/admin/links', adminOnly, async (req, res) => {
 const label = clean(req.body.label, 100); const code = String(req.body.code || '');
 const employeeHint = clean(req.body.employeeHint, 100);
 let expiresAt = null;
 if (req.body.expiresAt) {
  const d = new Date(req.body.expiresAt);
  if (!Number.isFinite(d.getTime()) || d.getTime() <= Date.now()) return res.status(400).json({ error: 'Expiry must be a future date.' });
  expiresAt = d.toISOString();
 }
 if (!label) return res.status(400).json({ error: 'Enter a link label.' });
 if (code.length < 6 || code.length > 100) return res.status(400).json({ error: 'Access code must be 6–100 characters.' });
 const token = randomToken(); const hash = await bcrypt.hash(code, 12);
 const result = db.prepare('INSERT INTO links (token,label,code_hash,employee_hint,expires_at) VALUES (?,?,?,?,?)').run(token,label,hash,employeeHint,expiresAt);
 res.status(201).json({ link: { id: result.lastInsertRowid, token, label, employeeHint, expiresAt, revoked: 0 }, shareUrl: `${req.protocol}://${req.get('host')}/upload/${token}` });
});
app.post('/api/admin/links/:id/revoke', adminOnly, (req, res) => {
 const row = db.prepare('UPDATE links SET revoked=1 WHERE id=?').run(Number(req.params.id));
 if (!row.changes) return res.status(404).json({ error: 'Link not found.' });
 res.json({ ok: true });
});
app.post('/api/admin/links/:id/enable', adminOnly, (req, res) => {
 const link = db.prepare('SELECT * FROM links WHERE id=?').get(Number(req.params.id));
 if (!link) return res.status(404).json({ error: 'Link not found.' });
 if (link.expires_at && new Date(link.expires_at).getTime() <= Date.now()) return res.status(400).json({ error: 'This link has expired. Create a new link.' });
 db.prepare('UPDATE links SET revoked=0 WHERE id=?').run(link.id); res.json({ ok: true });
});

app.post('/api/public/:token/verify', verifyLimiter, async (req, res) => {
 const link = getLink(clean(req.params.token, 100));
 if (!activeLink(link)) return res.status(404).json({ error: 'This upload link is invalid, expired, or disabled.' });
 const code = String(req.body.code || ''); const employeeName = clean(req.body.employeeName, 100);
 if (!employeeName) return res.status(400).json({ error: 'Enter your full name.' });
 if (!(await bcrypt.compare(code, link.code_hash))) return res.status(401).json({ error: 'Incorrect access code.' });
 req.session.uploadAccess = { linkId: link.id, token: link.token, employeeName, verifiedAt: Date.now() };
 req.session.save(err => err ? res.status(500).json({ error: 'Could not start upload session.' }) : res.json({ ok: true, employeeName, label: link.label }));
});
function uploadSession(req, res, next) {
 const a = req.session && req.session.uploadAccess;
 if (!a || a.token !== req.params.token || Date.now() - a.verifiedAt > 12 * 60 * 60 * 1000) return res.status(401).json({ error: 'Please verify your upload link and access code again.' });
 const link = getLink(a.token);
 if (!activeLink(link)) return res.status(403).json({ error: 'This upload link is no longer active.' });
 req.uploadAccess = a; req.uploadLink = link; next();
}
app.get('/api/public/:token/auth', uploadAuthLimiter, uploadSession, (_req, res) => res.json(imageKitAuth()));
app.post('/api/public/:token/record', uploadSession, (req, res) => {
 const b = req.body || {};
 const originalName = clean(b.name, 255); const url = String(b.url || ''); const fileId = clean(b.fileId, 200);
 const filePath = clean(b.filePath, 500); const mimeType = clean(b.mimeType, 150);
 const size = Number(b.size);
 if (!originalName || !url.startsWith('https://') || !fileId || !Number.isFinite(size) || size < 0) return res.status(400).json({ error: 'Invalid upload record.' });
 const result = db.prepare(`INSERT INTO uploads (link_id,employee_name,original_name,file_id,url,file_path,mime_type,size_bytes)
 VALUES (?,?,?,?,?,?,?,?)`).run(req.uploadAccess.linkId, req.uploadAccess.employeeName, originalName, fileId, url, filePath, mimeType, Math.floor(size));
 res.status(201).json({ ok: true, id: result.lastInsertRowid });
});
app.get('/api/public/:token/history', uploadSession, (req, res) => {
 const rows = db.prepare(`SELECT original_name,size_bytes,uploaded_at,status FROM uploads WHERE link_id=? AND employee_name=? ORDER BY id DESC LIMIT 200`).all(req.uploadAccess.linkId, req.uploadAccess.employeeName);
 res.json({ uploads: rows });
});

app.get('/api/admin/uploads', adminOnly, (req, res) => {
 const search = clean(req.query.search, 150); const page = Math.max(1, Math.min(100000, Number(req.query.page) || 1)); const limit = 50;
 const where = search ? `WHERE employee_name LIKE @q OR original_name LIKE @q OR file_path LIKE @q OR label LIKE @q` : '';
 const params = search ? { q: `%${search}%` } : {};
 const rows = db.prepare(`SELECT u.*,l.label AS link_label FROM uploads u JOIN links l ON l.id=u.link_id ${where} ORDER BY u.id DESC LIMIT ${limit} OFFSET ${(page-1)*limit}`).all(params);
 const total = db.prepare(`SELECT COUNT(*) AS n FROM uploads u JOIN links l ON l.id=u.link_id ${where}`).get(params).n;
 res.json({ uploads: rows, total, page, pages: Math.max(1, Math.ceil(total/limit)) });
});
app.get('/api/admin/employees', adminOnly, (_req, res) => {
 const employees = db.prepare(`SELECT employee_name,COUNT(*) AS file_count,COALESCE(SUM(size_bytes),0) AS total_bytes,MAX(uploaded_at) AS last_upload FROM uploads GROUP BY employee_name ORDER BY last_upload DESC`).all();
 res.json({ employees });
});
app.delete('/api/admin/uploads/:id', adminOnly, async (req, res) => {
 const row = db.prepare('SELECT * FROM uploads WHERE id=?').get(Number(req.params.id));
 if (!row) return res.status(404).json({ error: 'Upload record not found.' });
 try {
  await imagekitRequest(`https://api.imagekit.io/v1/files/${encodeURIComponent(row.file_id)}`, { method: 'DELETE' });
  db.prepare('DELETE FROM uploads WHERE id=?').run(row.id);
  res.json({ ok: true });
 } catch (e) { res.status(502).json({ error: `ImageKit delete failed: ${e.message}` }); }
});
app.get('/api/admin/imagekit-files', adminOnly, async (req, res) => {
 try {
  const page = Math.max(1, Math.min(1000, Number(req.query.page) || 1));
  const search = clean(req.query.search, 100);
  const qs = new URLSearchParams({ path: imagekitBase, limit: '100', skip: String((page-1)*100), sort: 'DESC_CREATED' });
  if (search) qs.set('searchQuery', `name : "${search.replace(/["\\]/g, '')}"`);
  const files = await imagekitRequest(`https://api.imagekit.io/v1/files?${qs.toString()}`);
  res.json({ files: Array.isArray(files) ? files : [], page });
 } catch (e) { res.status(502).json({ error: `Could not fetch ImageKit files: ${e.message}` }); }
});
app.get('/upload/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'upload.html')));
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Unexpected server error.' }); });
app.listen(PORT, () => console.log(`SohanSoft Employee Upload Portal running on port ${PORT}`));
