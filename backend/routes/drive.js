/**
 * routes/drive.js
 * Handles all Google Drive operations
 * GET/POST/PATCH/DELETE /drive/*
 */

const express = require('express');
const router  = express.Router();
const fetch   = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const { getDriveToken, requireAuth } = require('../shared/google');

// All Drive routes require auth
router.use(requireAuth);

// Proxy all Drive API requests
router.all('/*', async (req, res) => {
  try {
    const token    = await getDriveToken();
    const drivePath = req.path;
    const query    = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const url      = `https://www.googleapis.com/drive/v3${drivePath}${query}`;

    const headers = {
      Authorization:  `Bearer ${token}`,
      'Content-Type': req.headers['content-type'] || 'application/json',
    };

    const opts = { method: req.method, headers };
    if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
      opts.body = JSON.stringify(req.body);
    }

    const r  = await fetch(url, opts);
    const ct = r.headers.get('content-type') || '';

    res.status(r.status).set('content-type', ct);

    if (ct.includes('application/json')) {
      res.json(await r.json());
    } else {
      res.send(Buffer.from(await r.arrayBuffer()));
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
