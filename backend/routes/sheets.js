/**
 * routes/sheets.js
 * Google Sheets editor module
 *
 * GET  /sheets/:sheetId              → list sheet tabs
 * GET  /sheets/:sheetId/:tab         → read sheet data
 * POST /sheets/:sheetId/:tab         → write/update cell(s)
 * POST /sheets/:sheetId/:tab/append  → append a new row
 * DELETE /sheets/:sheetId/:tab/row/:rowIndex → delete a row
 */

const express = require('express');
const router  = express.Router();
const fetch   = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const { getDriveToken, requireAuth, requireRole } = require('../shared/google');

const BASE = 'https://sheets.googleapis.com/v4/spreadsheets';

// All sheet routes require auth
router.use(requireAuth);

// ── Helper ─────────────────────────────────────────────────────────
async function sheetsReq(path, opts = {}) {
  const tok = await getDriveToken();
  const r   = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      Authorization:  `Bearer ${tok}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.error?.message || r.statusText);
  }
  if (r.status === 204) return null;
  return r.json();
}

// GET /sheets/:sheetId — get spreadsheet metadata + tab list
router.get('/:sheetId', async (req, res) => {
  try {
    const data = await sheetsReq(`/${req.params.sheetId}?fields=sheets.properties`);
    const tabs = (data.sheets || []).map(s => ({
      id:    s.properties.sheetId,
      title: s.properties.title,
      index: s.properties.index,
      rows:  s.properties.gridProperties?.rowCount,
      cols:  s.properties.gridProperties?.columnCount,
    }));
    res.json({ sheetId: req.params.sheetId, tabs });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /sheets/:sheetId/:tab — read all data from a tab
router.get('/:sheetId/:tab', async (req, res) => {
  try {
    const range = encodeURIComponent(`${req.params.tab}`);
    const data  = await sheetsReq(`/${req.params.sheetId}/values/${range}`);
    res.json({
      range:  data.range,
      values: data.values || [],
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /sheets/:sheetId/:tab — update a specific range
// Body: { range: "A1:B2", values: [["val1","val2"]] }
router.post('/:sheetId/:tab', requireRole('superuser','admin'), async (req, res) => {
  try {
    const { range, values } = req.body;
    if (!range || !values) return res.status(400).json({ error: 'range and values required' });

    const fullRange = encodeURIComponent(`${req.params.tab}!${range}`);
    const data = await sheetsReq(
      `/${req.params.sheetId}/values/${fullRange}?valueInputOption=USER_ENTERED`,
      { method: 'PUT', body: JSON.stringify({ range: `${req.params.tab}!${range}`, values }) }
    );
    res.json({ updated: data.updatedCells, range: data.updatedRange });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /sheets/:sheetId/:tab/append — append a new row
// Body: { values: ["col1", "col2", "col3"] }
router.post('/:sheetId/:tab/append', requireRole('superuser','admin'), async (req, res) => {
  try {
    const { values } = req.body;
    if (!values) return res.status(400).json({ error: 'values required' });

    const range = encodeURIComponent(`${req.params.tab}`);
    const data  = await sheetsReq(
      `/${req.params.sheetId}/values/${range}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
      { method: 'POST', body: JSON.stringify({ values: [values] }) }
    );
    res.json({ appended: true, range: data.updates?.updatedRange });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /sheets/:sheetId/:tab/row/:rowIndex — delete a row (1-based index)
router.delete('/:sheetId/:sheetTabId/row/:rowIndex', requireRole('superuser'), async (req, res) => {
  try {
    const startIndex = parseInt(req.params.rowIndex) - 1; // convert to 0-based
    const data = await sheetsReq(`/${req.params.sheetId}:batchUpdate`, {
      method: 'POST',
      body: JSON.stringify({
        requests: [{
          deleteDimension: {
            range: {
              sheetId:    parseInt(req.params.sheetTabId),
              dimension:  'ROWS',
              startIndex,
              endIndex:   startIndex + 1,
            }
          }
        }]
      })
    });
    res.json({ deleted: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
