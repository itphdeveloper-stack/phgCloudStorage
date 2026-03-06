/**
 * shared/google.js
 * Shared utilities: Google OAuth token, session store, auth middleware
 * Used by all route modules
 */

const crypto = require('crypto');
const fetch  = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// ── Google OAuth token cache ───────────────────────────────────────
let cachedToken = null;
let tokenExpiry = 0;

async function getDriveToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
      grant_type:    'refresh_token',
    }),
  });

  const data = await r.json();
  if (!r.ok || !data.access_token)
    throw new Error('Token refresh failed: ' + (data.error_description || data.error));

  cachedToken = data.access_token;
  tokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedToken;
}

function getTokenExpiry() { return tokenExpiry; }

// ── Session store ──────────────────────────────────────────────────
const sessions   = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 hours

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

function deleteSession(token) { sessions.delete(token); }

// Clean expired sessions every hour
setInterval(() => {
  for (const [k, v] of sessions)
    if (Date.now() > v.expires) sessions.delete(k);
}, 60 * 60 * 1000);

// ── Auth middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token   = req.headers['x-session-token'];
  const session = validateSession(token);
  if (!session) return res.status(401).json({ error: 'Unauthorized — please log in' });
  req.session = session;
  next();
}

// ── Role helpers ───────────────────────────────────────────────────
const ROLES = { SUPERUSER: 'superuser', ADMIN: 'admin', USER: 'user' };

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.session?.role))
      return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ── Users cache (read from Google Sheet) ──────────────────────────
let usersCache     = null;
let usersCacheTime = 0;

async function getUsers() {
  if (usersCache && Date.now() - usersCacheTime < 60000) return usersCache;

  const tok = await getDriveToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${process.env.USERS_SHEET_ID}/values/Sheet1!A2:D200`;
  const r   = await fetch(url, { headers: { Authorization: `Bearer ${tok}` } });

  if (!r.ok) throw new Error('Could not read users sheet: ' + r.statusText);

  const data = await r.json();
  const rows = data.values || [];

  usersCache = rows
    .filter(row => row[0] && row[1] && row[2])
    .map(row => ({
      username:  row[0].trim().toLowerCase(),
      password:  row[1].trim(),
      role:      row[2].trim().toLowerCase(),
      folder_id: row[3] ? row[3].trim() : null,
    }));

  usersCacheTime = Date.now();
  console.log(`Loaded ${usersCache.length} users from sheet`);
  return usersCache;
}

module.exports = {
  getDriveToken,
  getTokenExpiry,
  createSession,
  validateSession,
  deleteSession,
  requireAuth,
  requireRole,
  getUsers,
  ROLES,
};
