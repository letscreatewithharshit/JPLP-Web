# JLPL (O&M) Portal

Operations and maintenance portal for GAIL's Jamnagar–Loni LPG Pipeline.

- **No outside dependencies.** Runs on Node.js alone (version 22.5 or later) with its built-in SQLite database. Nothing to `npm install`, and the pages load nothing from the internet.
- **Shared data** for every station, stored in one database file on your server.
- **Sign-in and roles**, either with portal accounts or with your Windows / Active Directory login through IIS or Apache.
- **Audit log** of every sign-in, change, upload and deletion.
- **English and Hindi** interface, text size controls, keyboard access, skip link, sitemap and accessibility page (GIGW).
- **Installable app** that keeps working offline. Records added offline, such as patrol reports, are sent when the device reconnects.

## Modules

| Area | Pages |
|---|---|
| Operations | Maintenance bases (station profile, daily shift checklist, equipment register, PM plan, contacts), shift logbook, ROU patrolling with GPS and photos, integrity calendar, spares inventory, instrumentation and calibration |
| Safety | Incidents and near misses, work permits, F&S training with seat booking, certifications with expiry alerts, live safety board on the home page |
| People | Contractor management (work orders, gate passes, police verification), telephone directory, organogram, vehicle sharing |
| Information | Documents and publications library with file upload, circulars on the home page, events calendar, notices ticker, quick links |
| Admin | Users and roles, notices and quick links, audit log, system status |

## Quick start

```bash
node --version          # must be 22.5 or later
node server.js          # starts on http://localhost:8080
```

On first run the server creates the user `admin` and prints its password in the console. Sign in and change it from the user menu, then add users under **Admin → Users**.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `HOST` | `0.0.0.0` | Address to listen on. Use `127.0.0.1` behind a reverse proxy |
| `DATA_DIR` | `./data` | Folder for the database (`jlpl.db`) and uploads |
| `AUTH_MODE` | `local` | `local` = portal accounts. `header` = trust the Windows/AD user passed by the reverse proxy |
| `AUTH_HEADER` | `X-Remote-User` | Header that carries the signed-in user in `header` mode |
| `ADMIN_USERS` | | In `header` mode, comma-separated usernames made administrators on first visit |
| `ADMIN_PASSWORD` | random | Initial `admin` password in `local` mode (first run only) |
| `COOKIE_SECURE` | `0` | Set to `1` once the site is served over HTTPS |
| `SESSION_HOURS` | `12` | Idle time before sign-out |
| `MAX_UPLOAD_MB` | `15` | Largest file that can be uploaded |

## Roles

| Role | Can do |
|---|---|
| Administrator | Everything, plus users, notices, quick links and the audit log |
| Station in-charge / engineer | Shift log, checklists, PM, equipment, spares, patrolling, integrity, calibration, permits, station contacts |
| Fire & Safety | Permits, investigating and closing incidents, certifications, training, safety figures |
| Human Resources | Events, documents, training, certifications, directory, organogram, notices |
| Security | Contracts, contract employees, gate passes, police verification, patrolling |
| Viewer | Read what is open to all staff, report incidents, share vehicles, book training seats |

The rules live in `PERMS` at the top of `server.js`. The server enforces them on every request; the browser only uses them to hide buttons. Contract employee records are visible to Security, HR and administrators only.

## Deploying on the GAIL intranet

1. Copy the whole folder to the server, for example `D:\jlpl-portal`.
2. Install Node.js 22 LTS (from nodejs.org, via your IT software centre).
3. Run it behind IIS or Apache so users get HTTPS on the usual port, with the portal itself listening on `127.0.0.1:8080`.

### Single sign-on with Windows / Active Directory (recommended)

With `AUTH_MODE=header`, people are signed in automatically with their domain account and nobody needs a separate password.

**IIS:** install URL Rewrite and Application Request Routing, enable Windows Authentication on the site, add a reverse-proxy rule to `http://127.0.0.1:8080`, allow the server variable `HTTP_X_REMOTE_USER`, and set it to `{LOGON_USER}` in the rule.

**Apache:** use `mod_auth_gssapi` (or `mod_auth_kerb`) for Kerberos, then
```apache
ProxyPass        / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
RequestHeader set X-Remote-User "%{REMOTE_USER}s"
```

Set `HOST=127.0.0.1` in this mode so nobody can reach the portal directly and fake the header. The server warns you if you forget. New people appear under Admin → Users as Viewers; give them a role there.

### Run as a service

**Windows:** use NSSM (`nssm install JLPLPortal "C:\Program Files\nodejs\node.exe" D:\jlpl-portal\server.js`, then set the environment variables on the Environment tab), or edit and run `start-windows.cmd` for a quick test.

**Linux (systemd):**
```ini
[Unit]
Description=JLPL portal
After=network.target
[Service]
WorkingDirectory=/opt/jlpl-portal
ExecStart=/usr/bin/node server.js
Environment=HOST=127.0.0.1 PORT=8080 AUTH_MODE=header COOKIE_SECURE=1
Restart=always
User=jlpl
[Install]
WantedBy=multi-user.target
```

## Backups

```bash
node backup.js                  # writes ./backups/<date-time>/ with jlpl.db and uploads
node backup.js E:\backups\jlpl  # or any folder
```
It is safe to run while the portal is live. Schedule it daily (Task Scheduler or cron) and copy the result off the server. To restore, stop the portal and put `jlpl.db` and `uploads` back into `DATA_DIR`.

## Fonts

The portal looks right with system fonts. For the intended typefaces, follow `public/assets/fonts/README.txt`.

## Security notes

- Passwords are hashed with scrypt. Sign-in is limited to 10 attempts per 15 minutes per address.
- Session cookies are HttpOnly and SameSite=Strict. Every change needs a custom request header, which blocks cross-site request forgery.
- A strict Content-Security-Policy allows scripts, styles and fonts from the portal itself only.
- Uploads are limited to PDF, image, Office, text and CSV files, stored outside the web folder and served only to signed-in users.
- Contractor employee data is personal data under the DPDP Act 2023: access is limited by role and every change is in the audit log.

## Demo copy

`node build-demo.js` writes `dist/jlpl-demo.html`, a single file that runs without the server and keeps data in the browser. Use it to show the portal before it is installed.

## Customising

- Stations, departments, milestones, LPG facts and leak steps: the `DATA` block at the top of `public/app.js`.
- Registers and their fields: `MODULES` in `public/app.js`. Add a field there and it appears in forms, tables, search and CSV export.
- Permissions: `PERMS` in `server.js` (and `DEMO_PERMS` in `app.js` for the demo copy).
- Hindi wording: the `HI` dictionary in `public/app.js`.
