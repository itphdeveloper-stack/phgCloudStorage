/**
 * routes/auth.js
 * Handles: POST /login, POST /logout, GET /token
 * Also aliased to / for backward compat with existing frontend
 */

const express = require('express');
const router  = express.Router();
const {
  getDriveToken, getTokenExpiry,
  createSession, deleteSession,
  requireAuth, getUsers,
} = require('../shared/google');

const VALID_ROLES = ['superuser', 'admin', 'user'];
const UPLOAD_FOLDER = process.env.UPLOAD_FOLDER_ID || 'root';

// POST /login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const users = await getUsers();
    const user  = users.find(u =>
      u.username === username.trim().toLowerCase() && u.password === password
    );

    if (!user)
      return res.status(401).json({ error: 'Invalid username or password' });

    if (!VALID_ROLES.includes(user.role))
      return res.status(403).json({ error: 'Invalid role assigned to this account' });

    const sessionToken = createSession({
      username:  user.username,
      role:      user.role,
      folder_id: user.folder_id,
    });

    res.json({
      session_token: sessionToken,
      username:      user.username,
      role:          user.role,
      folder_id:     user.folder_id || null,
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /logout
router.post('/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) deleteSession(token);
  res.json({ ok: true });
});

// GET /token — returns short-lived Drive access token to frontend
router.get('/token', requireAuth, async (req, res) => {
  try {
    const token = await getDriveToken();

    // Superuser gets the global upload folder, others get their assigned folder
    const uploadFolder = req.session.role === 'superuser'
      ? UPLOAD_FOLDER
      : (req.session.folder_id || UPLOAD_FOLDER);

    res.json({
      access_token:  token,
      upload_folder: uploadFolder,
      expires_in:    Math.floor((getTokenExpiry() - Date.now()) / 1000),
      role:          req.session.role,
      folder_id:     req.session.folder_id || null,
      username:      req.session.username,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
