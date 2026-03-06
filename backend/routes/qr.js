/**
 * routes/qr.js
 * QR Code generator for inventory management
 *
 * GET  /qr/generate?data=URL&label=ItemName  → returns QR as PNG (base64)
 * GET  /qr/item/:itemId                      → get item details from sheet
 * POST /qr/item                              → create new inventory item
 * PUT  /qr/item/:itemId                      → update inventory item
 *
 * Inventory sheet format (separate sheet from users):
 * A=item_id  B=name  C=description  D=location  E=quantity  F=notes  G=created_at
 */

const express = require('express');
const router  = express.Router();
const fetch   = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const { getDriveToken, requireAuth, requireRole } = require('../shared/google');

const INVENTORY_SHEET_ID = process.env.INVENTORY_SHEET_ID; // set when ready
const BASE_URL           = process.env.PORTAL_ORIGIN || 'https://your-portal.pages.dev';
const QR_API             = 'https://api.qrserver.com/v1/create-qr-code'; // free, no key needed

router.use(requireAuth);

// ── Helper: read inventory sheet ───────────────────────────────────
async function getInventoryRows() {
  if (!INVENTORY_SHEET_ID) throw new Error('INVENTORY_SHEET_ID env var not set');
  const tok = await getDriveToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${INVENTORY_SHEET_ID}/values/Sheet1!A2:G1000`;
  const r   = await fetch(url, { headers: { Authorization: `Bearer ${tok}` } });
  if (!r.ok) throw new Error('Could not read inventory sheet');
  const data = await r.json();
  return (data.values || []).map(row => ({
    item_id:     row[0] || '',
    name:        row[1] || '',
    description: row[2] || '',
    location:    row[3] || '',
    quantity:    row[4] || '',
    notes:       row[5] || '',
    created_at:  row[6] || '',
  }));
}

// GET /qr/generate?data=...&label=...&size=200
// Generates a QR code image URL pointing to the item's detail page
router.get('/generate', async (req, res) => {
  try {
    const { data, label, size = 200 } = req.query;
    if (!data) return res.status(400).json({ error: 'data param required' });

    // Build the QR target URL — points to portal item page
    const target  = data.startsWith('http') ? data : `${BASE_URL}/item/${data}`;
    const qrUrl   = `${QR_API}/?size=${size}x${size}&data=${encodeURIComponent(target)}&color=0-0-0&bgcolor=255-255-255&margin=10`;

    // Fetch the QR image and return as base64 so frontend can embed it
    const imgRes  = await fetch(qrUrl);
    if (!imgRes.ok) throw new Error('QR generation failed');
    const buffer  = await imgRes.arrayBuffer();
    const base64  = Buffer.from(buffer).toString('base64');

    res.json({
      qr_base64: `data:image/png;base64,${base64}`,
      qr_url:    qrUrl,
      target_url: target,
      label:     label || data,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /qr/items — list all inventory items
router.get('/items', async (req, res) => {
  try {
    const items = await getInventoryRows();
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /qr/item/:itemId — get single item details
router.get('/item/:itemId', async (req, res) => {
  try {
    const items = await getInventoryRows();
    const item  = items.find(i => i.item_id === req.params.itemId);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json({ item });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /qr/item — create new inventory item (superuser/admin only)
router.post('/item', requireRole('superuser', 'admin'), async (req, res) => {
  try {
    if (!INVENTORY_SHEET_ID) return res.status(503).json({ error: 'Inventory module not configured. Set INVENTORY_SHEET_ID env var.' });

    const { name, description, location, quantity, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    // Generate unique item ID
    const item_id    = 'ITM-' + Date.now();
    const created_at = new Date().toISOString().split('T')[0];
    const row        = [item_id, name, description||'', location||'', quantity||'', notes||'', created_at];

    const tok = await getDriveToken();
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${INVENTORY_SHEET_ID}/values/Sheet1:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;
    const r   = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: [row] }),
    });
    if (!r.ok) throw new Error('Failed to create item');

    // Generate QR for the new item
    const target  = `${BASE_URL}/item/${item_id}`;
    const qrUrl   = `${QR_API}/?size=200x200&data=${encodeURIComponent(target)}`;
    const imgRes  = await fetch(qrUrl);
    const base64  = Buffer.from(await imgRes.arrayBuffer()).toString('base64');

    res.json({
      item_id,
      item: { item_id, name, description, location, quantity, notes, created_at },
      qr_base64: `data:image/png;base64,${base64}`,
      target_url: target,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /qr/item/:itemId — update item details (superuser/admin only)
router.put('/item/:itemId', requireRole('superuser', 'admin'), async (req, res) => {
  try {
    if (!INVENTORY_SHEET_ID) return res.status(503).json({ error: 'Inventory module not configured' });

    const tok  = await getDriveToken();
    // Find the row number first
    const url  = `https://sheets.googleapis.com/v4/spreadsheets/${INVENTORY_SHEET_ID}/values/Sheet1!A:A`;
    const r    = await fetch(url, { headers: { Authorization: `Bearer ${tok}` } });
    const data = await r.json();
    const rows = data.values || [];
    const idx  = rows.findIndex(row => row[0] === req.params.itemId);
    if (idx < 0) return res.status(404).json({ error: 'Item not found' });

    const rowNum = idx + 1; // 1-based, and row 1 is header so idx=1 means row 2
    const { name, description, location, quantity, notes } = req.body;
    const range  = `Sheet1!B${rowNum}:F${rowNum}`;
    const putUrl = `https://sheets.googleapis.com/v4/spreadsheets/${INVENTORY_SHEET_ID}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`;
    const putR   = await fetch(putUrl, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ range, values: [[name||'', description||'', location||'', quantity||'', notes||'']] }),
    });
    if (!putR.ok) throw new Error('Failed to update item');

    res.json({ updated: true, item_id: req.params.itemId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
