const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const app     = express();

app.use(cors({
  origin: (origin, cb) => {
    const allowed = process.env.PORTAL_ORIGIN;
    if (!origin || !allowed || origin === allowed) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());

const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;
const UPLOAD_FOLDER = process.env.UPLOAD_FOLDER_ID || 'root';
const SHEET_ID      = process.env.USERS_SHEET_ID;
const PORT          = process.env.PORT || 3000;

// ── Google token ──────────────────────────────────────────────────
let cachedToken = null, tokenExpiry = 0;

async function getDriveToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, refresh_token: REFRESH_TOKEN, grant_type: 'refresh_token' }).toString(),
  });
  const data = await r.json();
  if (!r.ok || !data.access_token) throw new Error('Token refresh failed: ' + (data.error_description || data.error));
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedToken;
}

// ── Sessions ──────────────────────────────────────────────────────
const sessions = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { ...user, expires: Date.now() + SESSION_TTL });
  return token;
}
function validateSession(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(token); return null; }
  return s;
}
function requireAuth(req, res, next) {
  const s = validateSession(req.headers['x-session-token']);
  if (!s) return res.status(401).json({ error: 'Unauthorized' });
  req.session = s; next();
}

// ── Users from Sheet ──────────────────────────────────────────────
let usersCache = null, usersCacheTime = 0;

async function getUsers() {
  if (usersCache && Date.now() - usersCacheTime < 60000) return usersCache;
  const tok = await getDriveToken();
  const r = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Sheet1!A2:D200`, {
    headers: { Authorization: `Bearer ${tok}` }
  });
  if (!r.ok) throw new Error('Could not read users sheet: ' + r.statusText);
  const data = await r.json();
  usersCache = (data.values || [])
    .filter(row => row[0] && row[1] && row[2])
    .map(row => ({ username: row[0].trim().toLowerCase(), password: row[1].trim(), role: row[2].trim().toLowerCase(), folder_id: row[3]?.trim() || null }));
  usersCacheTime = Date.now();
  return usersCache;
}

// ── Routes ────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const users = await getUsers();
    const user = users.find(u => u.username === username.trim().toLowerCase() && u.password === password);
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const sessionToken = createSession({ username: user.username, role: user.role, folder_id: user.folder_id });
    res.json({ session_token: sessionToken, username: user.username, role: user.role, folder_id: user.folder_id || null });
  } catch (e) { console.error('Login error:', e); res.status(500).json({ error: e.message }); }
});

app.post('/logout', (req, res) => {
  sessions.delete(req.headers['x-session-token']);
  res.json({ ok: true });
});

app.get('/token', requireAuth, async (req, res) => {
  try {
    const token = await getDriveToken();
    const uploadFolder = req.session.role === 'superuser' ? UPLOAD_FOLDER : (req.session.folder_id || UPLOAD_FOLDER);
    res.json({ access_token: token, upload_folder: uploadFolder, expires_in: Math.floor((tokenExpiry - Date.now()) / 1000), role: req.session.role, folder_id: req.session.folder_id || null, username: req.session.username, users_sheet_id: SHEET_ID });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.all('/sheets/*', requireAuth, async (req, res) => {
  try {
    const tok = await getDriveToken();
    const path = req.path.replace('/sheets', '');
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url = `https://sheets.googleapis.com/v4/spreadsheets${path}${qs}`;
    const opts = { method: req.method, headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' } };
    if (['POST','PUT','PATCH'].includes(req.method) && req.body) opts.body = JSON.stringify(req.body);
    const r = await fetch(url, opts);
    const ct = r.headers.get('content-type') || '';
    res.status(r.status).set('content-type', ct);
    ct.includes('application/json') ? res.json(await r.json()) : res.send(Buffer.from(await r.arrayBuffer()));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/qr/generate', requireAuth, async (req, res) => {
  try {
    const { data, size = 200 } = req.query;
    if (!data) return res.status(400).json({ error: 'data param required' });
    const target = data.startsWith('http') ? data : `${process.env.PORTAL_ORIGIN}/item/${data}`;
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(target)}`;
    const imgRes = await fetch(qrUrl);
    const base64 = Buffer.from(await imgRes.arrayBuffer()).toString('base64');
    res.json({ qr_base64: `data:image/png;base64,${base64}`, target_url: target });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅  PHG Portal running on port ${PORT}`));
}

module.exports = app;
