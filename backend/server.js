/**
 * PHG Cloud Portal — Backend
 *
 * Modular architecture — each feature is a separate route file:
 *   /auth    → login, logout, session validation
 *   /drive   → Google Drive file portal
 *   /sheets  → Google Sheets editor
 *   /qr      → QR code generator
 *   /invoice → (future) invoicing module
 */

const express = require('express');
const cors    = require('cors');
const app     = express();
const PORT    = process.env.PORT || 3000;

// ── Validate required env vars ─────────────────────────────────────
const required = ['GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','GOOGLE_REFRESH_TOKEN','USERS_SHEET_ID'];
const missing  = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error('❌  Missing env vars:', missing.join(', '));
  process.exit(1);
}

// ── CORS ───────────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => {
    const allowed = process.env.PORTAL_ORIGIN;
    if (!origin || !allowed || origin === allowed) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());

// ── Health check ───────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  modules: ['auth', 'drive', 'sheets', 'qr']
}));

// ── Mount modules ──────────────────────────────────────────────────
app.use('/auth',   require('./routes/auth'));
app.use('/drive',  require('./routes/drive'));
app.use('/sheets', require('./routes/sheets'));
app.use('/qr',     require('./routes/qr'));

// Legacy aliases so existing frontend (/login, /logout, /token) still works
app.use('/', require('./routes/auth'));

// ── Global error handler ───────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Export for Vercel serverless — also works locally with node server.js
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`✅  PHG Portal running on port ${PORT}`);
    console.log(`   Active modules: auth | drive | sheets | qr`);
  });
}

module.exports = app;
