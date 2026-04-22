const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { Redis } = require('@upstash/redis');
const app     = express();

app.use(cors({
  origin: (origin, cb) => {
    const allowed = process.env.PORTAL_ORIGIN; // e.g. https://phgcloudstorage.pages.dev
    const allowedHost = allowed ? allowed.replace(/^https?:\/\//, '') : null;
    // allowedHost = "phgcloudstorage.pages.dev"
    // Cloudflare preview URLs come in two forms:
    //   https://<hash>.phgcloudstorage.pages.dev   (subdomain match)
    //   https://<hash>-phgcloudstorage.pages.dev   (dash-separated on pages.dev)
    const projectSlug = allowedHost ? allowedHost.replace('.pages.dev', '') : null;
    const isPreview = projectSlug && origin &&
      new RegExp(`^https://[a-z0-9]+-${projectSlug}\\.pages\\.dev$`).test(origin);
    const isAllowed =
      !origin ||
      origin === allowed ||
      (allowedHost && origin.endsWith('.' + allowedHost)) ||
      isPreview;
    isAllowed ? cb(null, true) : cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());

const SA_EMAIL      = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
const SA_KEY = (() => {
  let k = process.env.GOOGLE_PRIVATE_KEY || '';
  k = k.replace(/\\n/g, '\n');
  if (k.includes('-----BEGIN PRIVATE KEY-----') && !k.includes('\n-----END')) {
    k = k.replace('-----BEGIN PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----\n')
         .replace('-----END PRIVATE KEY-----', '\n-----END PRIVATE KEY-----\n');
  }
  return k;
})();
const UPLOAD_FOLDER         = process.env.UPLOAD_FOLDER_ID || 'root';
const SHEET_ID              = process.env.USERS_SHEET_ID;
const INV_SHEET_ID          = process.env.INV_SHEET_ID || '';
const INV_PHOTOS_FOLDER     = process.env.INV_PHOTOS_FOLDER || '';
const MAIL_FOLDER_ID        = process.env.MAIL_FOLDER_ID || '';
const MAIL_ATTACH_FOLDER_ID = process.env.MAIL_ATTACH_FOLDER_ID || '';
const PORT                  = process.env.PORT || 3000;

// ── Upstash Redis (persists OAuth2 refresh token across all instances) ──
const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_KV_REST_API_URL,
  token: process.env.UPSTASH_REDIS_KV_REST_API_TOKEN,
});
const KV_REFRESH_TOKEN_KEY = 'oauth_refresh_token';

// ── Service Account token (Sheets only) ──────────────────────────
let cachedSAToken = null, saTokenExpiry = 0;

async function getSheetsToken() {
  if (cachedSAToken && Date.now() < saTokenExpiry - 60000) return cachedSAToken;

  if (!SA_EMAIL || !SA_KEY) throw new Error('Service account credentials not configured');

  const SCOPES = 'https://www.googleapis.com/auth/spreadsheets';
  const now = Math.floor(Date.now() / 1000);

  const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: SA_EMAIL,
    scope: SCOPES,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })).toString('base64url');

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const signature = sign.sign(SA_KEY, 'base64url');
  const jwt = `${header}.${payload}.${signature}`;

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }).toString(),
  });

  const data = await r.json();
  if (!r.ok || !data.access_token) throw new Error('Service account token failed: ' + (data.error_description || data.error));
  cachedSAToken = data.access_token;
  saTokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedSAToken;
}

// ── OAuth2 Drive token (all Drive operations) ─────────────────────
let cachedDriveToken = null, driveTokenExpiry = 0;

async function getDriveOAuthToken() {
  if (cachedDriveToken && Date.now() < driveTokenExpiry - 60000) return cachedDriveToken;

  const clientId     = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;

  if (!clientId || !clientSecret) throw new Error('OAuth credentials not configured (OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET)');

  // Read refresh token from Upstash first, fall back to env var on very first run
  let refreshToken = null;
  try {
    refreshToken = await redis.get(KV_REFRESH_TOKEN_KEY);
  } catch (e) {
    console.warn('Upstash read failed, falling back to env var:', e.message);
  }

  if (!refreshToken) {
    refreshToken = process.env.OAUTH_REFRESH_TOKEN;
    if (!refreshToken) throw new Error('No OAuth refresh token found in Upstash or env vars');
    // Seed Upstash with env var value on first run
    try { await redis.set(KV_REFRESH_TOKEN_KEY, refreshToken); } catch (e) { console.warn('Upstash seed failed:', e.message); }
  }

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type:    'refresh_token',
    }).toString(),
  });

  const data = await r.json();
  if (!r.ok || !data.access_token) throw new Error('Drive OAuth token failed: ' + (data.error_description || data.error));

  // If Google rotates the refresh token, save new one to Upstash immediately
  if (data.refresh_token && data.refresh_token !== refreshToken) {
    console.log('Google rotated refresh token — saving new one to Upstash');
    try { await redis.set(KV_REFRESH_TOKEN_KEY, data.refresh_token); } catch (e) { console.warn('Upstash rotation save failed:', e.message); }
  }

  cachedDriveToken = data.access_token;
  driveTokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedDriveToken;
}

// ── Sessions (Redis-backed, sliding expiry) ───────────────────────
const SESSION_TTL_SEC = 8 * 60 * 60; // 8 hours in seconds

async function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  await redis.set(`session:${token}`, JSON.stringify(user), { ex: SESSION_TTL_SEC });
  return token;
}
async function validateSession(token) {
  if (!token) return null;
  try {
    const raw = await redis.get(`session:${token}`);
    if (!raw) return null;
    // Slide the expiry on every use — keeps active users logged in
    await redis.expire(`session:${token}`, SESSION_TTL_SEC);
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch (e) {
    console.warn('Session Redis error:', e.message);
    return null;
  }
}
async function deleteSession(token) {
  if (token) await redis.del(`session:${token}`).catch(()=>{});
}
function requireAuth(req, res, next) {
  validateSession(req.headers['x-session-token']).then(s => {
    if (!s) return res.status(401).json({ error: 'Unauthorized' });
    req.session = s; next();
  }).catch(() => res.status(401).json({ error: 'Unauthorized' }));
}

// ── Password hashing ─────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}
// Accepts both plain-text (legacy) and sha256-hashed passwords
function passwordMatches(input, stored) {
  return stored === input || stored === sha256(input);
}

// ── Users from Sheet (service account) ───────────────────────────
let usersCache = null, usersCacheTime = 0;

async function getUsers() {
  if (usersCache && Date.now() - usersCacheTime < 60000) return usersCache;
  const tok = await getSheetsToken();
  const r = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Sheet1!A2:G200`, {
    headers: { Authorization: `Bearer ${tok}` }
  });
  if (!r.ok) throw new Error('Could not read users sheet: ' + r.statusText);
  const data = await r.json();
  usersCache = (data.values || [])
    .filter(row => row[0] && row[1] && row[2])
    // Columns: A=username, B=password, C=role, D=folder_id, E=branch, F=position, G=email
    .map(row => ({
      username:  row[0].trim().toLowerCase(),
      password:  row[1].trim(),
      role:      row[2].trim().toLowerCase(),
      folder_id: row[3]?.trim() || null,
      branch:    row[4]?.trim() || '',
      position:  row[5]?.trim() || '',
      email:     row[6]?.trim().toLowerCase() || '',
    }));
  usersCacheTime = Date.now();
  return usersCache;
}

// ── Routes ────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const users = await getUsers();
    const user = users.find(u => u.email === email.trim().toLowerCase() && passwordMatches(password, u.password));
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const sessionToken = await createSession({ username: user.username, email: user.email, role: user.role, folder_id: user.folder_id });
    res.json({ session_token: sessionToken, username: user.username, email: user.email, role: user.role, folder_id: user.folder_id || null });
  } catch (e) { console.error('Login error:', e); res.status(500).json({ error: e.message }); }
});

app.post('/logout', async (req, res) => {
  await deleteSession(req.headers['x-session-token']);
  res.json({ ok: true });
});

// ── /token — OAuth2 Drive token (used by all frontend Drive calls) ─
app.get('/token', requireAuth, async (req, res) => {
  try {
    const token = await getDriveOAuthToken();
    const uploadFolder = req.session.role === 'superuser' ? UPLOAD_FOLDER : (req.session.folder_id || UPLOAD_FOLDER);
    res.json({
      access_token:           token,
      upload_folder:          uploadFolder,
      expires_in:             Math.floor((driveTokenExpiry - Date.now()) / 1000),
      role:                   req.session.role,
      folder_id:              req.session.folder_id || null,
      username:               req.session.username,
      email:                  req.session.email || '',
      users_sheet_id:         SHEET_ID,
      inv_sheet_id:           INV_SHEET_ID,
      inv_photos_folder:      INV_PHOTOS_FOLDER,
      mail_folder_id:         MAIL_FOLDER_ID,
      mail_attach_folder_id:  MAIL_ATTACH_FOLDER_ID,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── /sheets/* — Sheets API proxy (service account) ────────────────
app.all('/sheets/*', requireAuth, async (req, res) => {
  try {
    const tok = await getSheetsToken();
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

// ── Bust users cache (call after saving/changing passwords) ───────
app.post('/users/bust-cache', requireAuth, (req, res) => {
  usersCache = null; usersCacheTime = 0;
  res.json({ ok: true });
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

// ── Activity Log (service account — Sheets only) ──────────────────
app.post('/log', requireAuth, async (req, res) => {
  try {
    const { action, detail = '' } = req.body;
    if (!action) return res.status(400).json({ error: 'action required' });
    if (!SHEET_ID) return res.status(500).json({ error: 'SHEET_ID not configured' });
    const tok = await getSheetsToken();
    const now = new Date();
    const timeStr = now.toLocaleString('en-GB', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit', timeZone:'Asia/Jakarta' });
    const user = req.session.email || req.session.username || '—';
    const r = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Sheet3!A:D:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: [[timeStr, user, action, detail]] })
    });
    if (!r.ok) { const txt=await r.text(); let msg='Sheets append failed'; try{msg=JSON.parse(txt).error?.message||msg;}catch(_){} return res.status(500).json({ error: msg }); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/log', requireAuth, async (req, res) => {
  try {
    if (!SHEET_ID) return res.status(500).json({ error: 'SHEET_ID not configured' });
    const tok = await getSheetsToken();
    const r = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Sheet3!A2:D`, {
      headers: { Authorization: `Bearer ${tok}` }
    });
    const data = await r.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const rows = (data.values || []).filter(r => r[0]);
    // Parse "DD/MM/YYYY, HH:MM:SS" correctly
    const parseLogDate = str => {
      const m = str && str.match(/(\d{2})\/(\d{2})\/(\d{4}),?\s*(\d{2}):(\d{2}):(\d{2})/);
      if (!m) return null;
      return new Date(+m[3], +m[2]-1, +m[1], +m[4], +m[5], +m[6]);
    };
    const cutoff = new Date(Date.now() - 72*60*60*1000);
    const filtered = rows.filter(r => { const d = parseLogDate(r[0]); return d && d >= cutoff; });
    res.json({ rows: filtered.reverse() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ── Public item detail (no auth — for QR scan) ───────────────────
app.get('/item/:id', async (req, res) => {
  try {
    const itemId = req.params.id;
    if (!INV_SHEET_ID) return res.status(500).json({ error: 'INV_SHEET_ID not configured' });
    const tok = await getSheetsToken();

    // Read inventory sheet
    const sheetR = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${INV_SHEET_ID}/values/Sheet1!A2:H500`, {
      headers: { Authorization: `Bearer ${tok}` }
    });
    const sheetData = await sheetR.json();
    if (sheetData.error) return res.status(500).json({ error: sheetData.error.message });

    const row = (sheetData.values || []).find(r => r[0] === itemId);
    if (!row) return res.status(404).json({ error: 'Item not found' });

    const item = {
      id: row[0]||'', name: row[1]||'', spec: row[2]||'',
      branch: row[3]||'', position: row[4]||'', assigned: row[5]||'',
      dateBought: row[6]||'', dateRecorded: row[7]||''
    };

    // Get photo file IDs from Drive
    let photos = [];
    try {
      const driveTok = await getDriveOAuthToken();
      const q = encodeURIComponent(`'${INV_PHOTOS_FOLDER}' in parents and name contains '${itemId}_' and trashed=false`);
      const driveR = await fetch(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name,mimeType)&orderBy=name&supportsAllDrives=true`, {
        headers: { Authorization: `Bearer ${driveTok}` }
      });
      const driveData = await driveR.json();
      photos = (driveData.files || []).filter(f => f.mimeType.startsWith('image/')).map(f => f.id);
    } catch(e) { /* photos optional */ }

    res.json({ item, photos });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── /file/:id — Public Drive file proxy (for QR scan photo display) ─
// Streams Drive files through the backend using OAuth token,
// so unauthenticated visitors can view inventory photos via QR scan.
app.get('/file/:id', async (req, res) => {
  try {
    const tok = await getDriveOAuthToken();
    const fileId = req.params.id;

    // First get file metadata to validate it's an image
    const metaR = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?fields=mimeType,name&supportsAllDrives=true`, {
      headers: { Authorization: `Bearer ${tok}` }
    });
    if (!metaR.ok) return res.status(metaR.status).json({ error: 'File not found' });
    const meta = await metaR.json();
    if (!meta.mimeType?.startsWith('image/')) return res.status(403).json({ error: 'Only image files can be proxied' });

    // Stream the file content
    const fileR = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media&supportsAllDrives=true`, {
      headers: { Authorization: `Bearer ${tok}` }
    });
    if (!fileR.ok) return res.status(fileR.status).json({ error: 'Could not fetch file' });

    res.set('Content-Type', meta.mimeType);
    res.set('Cache-Control', 'public, max-age=3600'); // cache 1hr in browser/CDN

    // Stream response body to client
    const reader = fileR.body.getReader();
    const pump = async () => {
      const { done, value } = await reader.read();
      if (done) { res.end(); return; }
      res.write(Buffer.from(value));
      await pump();
    };
    await pump();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// /users/info endpoint removed — login now uses email, branch/position no longer shown on login screen

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅  PHG Portal running on port ${PORT}`));
}

module.exports = app;
