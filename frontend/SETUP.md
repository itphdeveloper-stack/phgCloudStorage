# PHG Cloud Portal — Setup Guide

## How it works

```
Employee opens portal → portal asks backend for token → backend uses YOUR refresh token → files upload to YOUR Drive
```

Employees never log in. They just open the portal and upload.

---

## STEP 1 — Create Google OAuth Credentials

1. Go to https://console.cloud.google.com
2. Select or create a project
3. Go to **APIs & Services → Library**
4. Search "Google Drive API" → Enable it
5. Go to **APIs & Services → Credentials**
6. Click **"+ Create Credentials" → OAuth client ID**
7. Application type: **Web application**
8. Name: `PHG Portal`
9. Under **Authorized redirect URIs**, add:
   `https://developers.google.com/oauthplayground`
10. Click **Create** — note your **Client ID** and **Client Secret**

---

## STEP 2 — Get Your Refresh Token (one-time, takes 2 minutes)

1. Go to https://developers.google.com/oauthplayground
2. Click the ⚙️ gear (top right) → check **"Use your own OAuth credentials"**
3. Enter your **Client ID** and **Client Secret**
4. In the left panel, find **"Drive API v3"** → select:
   - `https://www.googleapis.com/auth/drive`
5. Click **"Authorize APIs"** → sign in with YOUR Google account (the one with 200GB)
6. Click **"Exchange authorization code for tokens"**
7. Copy the **Refresh token** — save it somewhere safe

---

## STEP 3 — Deploy the Backend to Railway (free)

1. Go to https://railway.app and sign up (free)
2. Click **"New Project" → "Deploy from GitHub repo"**
   - Or use **"Deploy from template"** → Node.js
3. Upload the `backend/` folder contents (server.js, package.json)
4. Go to your project → **Variables** tab → add:

   ```
   GOOGLE_CLIENT_ID      = (from Step 1)
   GOOGLE_CLIENT_SECRET  = (from Step 1)
   GOOGLE_REFRESH_TOKEN  = (from Step 2)
   UPLOAD_FOLDER_ID      = (optional: folder ID from your Drive URL)
   PORT                  = 3000
   ```

5. Railway will give you a URL like:
   `https://phg-portal-backend.up.railway.app`

> **Alternative: Render.com** — also free, same process.

---

## STEP 4 — Configure the Portal

Open `frontend/index.html` and find line ~165:

```javascript
const BACKEND_URL = 'https://YOUR-BACKEND-URL.railway.app'; // ← CHANGE THIS
```

Replace with your Railway URL:

```javascript
const BACKEND_URL = 'https://phg-portal-backend.up.railway.app';
```

---

## STEP 5 — Deploy the Portal

**Option A: Host on Netlify (free, drag & drop)**
1. Go to https://netlify.com
2. Drag the `frontend/` folder onto the Netlify dashboard
3. Done — you get a URL like `https://phg-portal.netlify.app`

**Option B: Host on GitHub Pages (free)**
1. Create a GitHub repo
2. Push the `frontend/` folder contents
3. Go to repo Settings → Pages → set source to main branch

**Option C: Just open the file locally**
- Double-click `frontend/index.html` — works fine from your computer

---

## STEP 6 — Optional: Set an Upload Folder

If you want all employee uploads to go to a specific folder (recommended):

1. Create a folder in your Google Drive (e.g. "Employee Uploads")
2. Open that folder — note the ID in the URL:
   `https://drive.google.com/drive/folders/`**`1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs`**
3. Add to Railway env vars:
   `UPLOAD_FOLDER_ID = 1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs`

---

## Security Notes

- ✅ Employees never see your Google credentials
- ✅ The backend only exposes short-lived access tokens (1 hour)
- ✅ Your refresh token lives only on Railway (server-side)
- ⚠️  Add `PORTAL_ORIGIN=https://your-portal.netlify.app` to backend env to restrict CORS
- ⚠️  Anyone with the portal URL can upload to your Drive — share only with employees

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Backend unreachable" | Check Railway deployment is running, verify BACKEND_URL in portal |
| "Token refresh failed" | Re-generate refresh token (Step 2) — they expire if unused |
| "403 on upload" | Make sure Drive API is enabled in Google Cloud Console |
| Files go to wrong folder | Set UPLOAD_FOLDER_ID in Railway env vars |
