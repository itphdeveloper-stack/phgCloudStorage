/**
 * PHG Cloud Portal - Backend Proxy
 * 
 * This server holds your Google OAuth refresh token and proxies
 * Drive API requests from your employees' portal sessions.
 * Employees never see your credentials.
 */

const express = require('express');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const app = express();

app.use(cors({ origin: process.env.PORTAL_ORIGIN || '*' }));
app.use(express.json());

// ── Config from environment variables ──
const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;
const PORT          = process.env.PORT || 3000;
const UPLOAD_FOLDER = process.env.UPLOAD_FOLDER_ID || 'root'; // Default Drive folder for uploads

if (!CLIENT_ID || !CLIENT_SECRET || !REFRESH_TOKEN) {
  console.error('❌  Missing required env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN');
  process.exit(1);
}

// ── Token cache ──
let cachedToken = null;
let tokenExpiry  = 0;

async function getAccessToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: REFRESH_TOKEN,
      grant_type:    'refresh_token',
    }),
  });

  const data = await r.json();
  if (!r.ok || !data.access_token) {
    throw new Error('Token refresh failed: ' + (data.error_description || data.error));
  }

  cachedToken = data.access_token;
  tokenExpiry  = Date.now() + (data.expires_in * 1000);
  return cachedToken;
}

// ── Health check ──
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Get access token for the portal (short-lived, safe to expose) ──
app.get('/token', async (req, res) => {
  try {
    const token = await getAccessToken();
    // Only expose the token - never expose refresh token or secrets
    res.json({ 
      access_token: token, 
      upload_folder: UPLOAD_FOLDER,
      expires_in: Math.floor((tokenExpiry - Date.now()) / 1000)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Proxy Drive API requests (GET/PATCH/DELETE - not uploads) ──
app.all('/drive/*', async (req, res) => {
  try {
    const token = await getAccessToken();
    const drivePath = req.path.replace('/drive', '');
    const url = `https://www.googleapis.com/drive/v3${drivePath}${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`;

    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': req.headers['content-type'] || 'application/json',
    };

    const fetchOpts = {
      method: req.method,
      headers,
    };

    if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
      fetchOpts.body = JSON.stringify(req.body);
    }

    const r = await fetch(url, fetchOpts);
    const ct = r.headers.get('content-type') || '';

    res.status(r.status);
    res.set('content-type', ct);

    if (ct.includes('application/json')) {
      const data = await r.json();
      res.json(data);
    } else {
      const buf = await r.arrayBuffer();
      res.send(Buffer.from(buf));
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅  PHG Portal backend running on port ${PORT}`);
  console.log(`   Upload folder: ${UPLOAD_FOLDER}`);
});
