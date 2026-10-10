# Myphema – browser extension + backend

## 1. Start the backend (Python 3.9+)
- Windows: double-click `run.bat`   |   Mac/Linux: `./run.sh`
- It opens on http://localhost:5000 (you can also use the full app there, in a normal browser tab).
- `DEV_MODE=1` (set by the scripts) shows OTP codes on screen. For real emails, set the SMTP values from `backend/.env.example`
  and remove DEV_MODE.

## 2. Install the extension (Chrome / Edge / Brave)
1. Open `chrome://extensions` (Edge: `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and choose the `extension` folder.
3. Click the Myphema icon in the toolbar. The app opens in a tab. Create an account (confirm password + OTP) or sign in.
   The login screen has a **Server URL** box (default `http://localhost:5000`) if your backend runs elsewhere.

## 3. See it detect something
- Open http://localhost:5000/static/test-upload.html (or a real site such as wetransfer.com) and pick or drop a few files.
- A banner confirms the report, the toolbar badge shows the open-alert count, and a new alert appears under **Alerts**
  (uploads to known file-sharing sites score high; Block transfer / Resolve / Mark safe all work and are logged in **History**).

## What the extension reports
Only the **domain, file names and file sizes** when a user selects or drops files on a page. Never file contents.
Tell your staff it is installed. Uploads to domains listed in `ALLOWED_DOMAINS` (backend setting) are ignored.

## Layout
- `backend/` Flask + SQLite API (`app.py`), tests (`python test_api.py`), and the same web app in `static/`.
- `extension/` Manifest V3 extension: `app.html` + `app.js` (the UI), `background.js`, `content.js`.

## Good to know
- Employees, Endpoints and the starting alerts are sample data; your own uploads and actions are real and stored in `backend/myphema.db`.
- Uploads inside iframes are not monitored. The extension reports uploads, it does not block them.
- Before real use: HTTPS, your own `JWT_SECRET`, `ALLOWED_ORIGIN` set to your site, DEV_MODE off, `gunicorn app:app`.
