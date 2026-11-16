# TOIL Tracker

A small internal web application for tracking **TOIL (Time Off In Lieu)**: hours banked by working outside normal hours, and hours taken back as time off. Teams, managers, reporting and a full audit trail are built in.

*Last updated: November 2026*

---

## 1. Contents

1. [Features](#2-features)
2. [Architecture and requirements](#3-architecture-and-requirements)
3. [Deployment](#4-deployment)
4. [Configuration reference](#5-configuration-reference)
5. [Microsoft Entra ID (Azure AD) sign-in and MFA](#6-microsoft-entra-id-azure-ad-sign-in-and-mfa)
6. [First run and user administration](#7-first-run-and-user-administration)
7. [Operations: monitoring, backup, restore, upgrade](#8-operations)
8. [Security](#9-security)
9. [Troubleshooting](#10-troubleshooting)
10. [Known limitations](#11-known-limitations)
11. [Production go-live checklist](#12-production-go-live-checklist)
12. [Data model](#13-data-model)

---

## 2. Features

**Tracking time**
- Each person adds **earned** (banked) and **taken** (time off) entries with a date, hours and reason.
- A reason is required for earned time and optional for time off.
- **Multi-day time off:** choose a date range and hours per day (default 8). One entry is created per day, optionally skipping weekends (up to 60 days at once). Each day can be edited or deleted individually.
- Live balance on the *My TOIL* page. Future-dated time off is deducted as soon as it is booked.
- Dates are limited to 1 Jan 2026 – 31 Dec 2100; a single entry is limited to 24 hours.

**Teams and roles**
- Any number of **teams**. A person can belong to several teams, and a team can have several managers.
- Four roles, chosen when a user is added (and editable later): **Teammate**, **Team lead**, **Director**, **Admin**.
  - *Teammate*: manages their own entries and sees their own report.
  - *Team lead / Director*: everything a teammate can do, plus a **Teams** tab for the teams they manage: balances per person, drill-down into entries, and corrections on behalf of team members. (Leads and directors currently have identical permissions; the title is a label.)
  - *Admin*: sees every team and report, creates teams, adds/edits/removes users, resets passwords and changes settings.
- Users have a **full name** (shown in reports, tables and the audit trail). It falls back to the email address if blank.

**Corrections and audit trail**
- Managers and admins can add, edit or delete a team member's entries. A **note explaining the change is mandatory**.
- Every entry create, edit and delete (including people's own) is recorded with who, when, before/after values and the note. Owners and their managers see this on the **History** panel. Audit rows are never deleted by the application.
- **Admin activity log** (Admin tab): users added, changed or removed, role and team changes, password resets, Microsoft account links, team creation/deletion and settings changes are recorded with who and when. Passwords are never logged.

**Reports** (browser-based, no external services)
- Tiles: *Remaining today*, *Booked upcoming*, *Left after booked time off*, *Total earned*, *Total taken*.
- Charts: earned vs taken per month, and remaining hours at the end of each month (projected into upcoming months, with a "Today" marker).
- Month-by-month table, and a per-person remaining-hours table for team reports.
- Managers choose a whole team or an individual; teammates see their own report.
- **Yearly report** (own tab): pick a calendar year and a person or team. It shows the opening balance on 1 January (carried over from earlier years), hours earned and taken, booked future time off, the closing balance on 31 December, month-by-month charts and table, a per-person table for teams, and every entry with its reason. Download it as **CSV** (spreadsheet-safe: text cells that start with `=`, `+`, `-` or `@` are neutralised) or use **Print / save as PDF**, which hides the navigation and uses a print layout.

**Admin settings**
- **Branding:** admins set the application name and upload a logo (PNG, JPEG or WebP, up to 512 KB) from the Admin tab. They appear on the login screen, in the header and in the browser tab. SVG logos are refused because they can carry script and the login page is public. The logo is stored in the database, so it is included in backups.
- **Allow negative balances** (default on). When off, any change that would push someone's balance below zero is blocked, including time off, edits and deletion of earned time already used. People already below zero can still recover by adding earned time or removing time off.

**Sign-in**
- **Microsoft Entra ID (Azure AD)** single sign-on. MFA is enforced by your tenant's Conditional Access policy.
- **Local email/password** accounts (optional, can be disabled). Passwords are bcrypt-hashed, minimum 10 characters, with brute-force lockout.
- Either or both methods can be enabled. Only users an admin has added can sign in, even if they authenticate successfully with Entra.

---

## 3. Architecture and requirements

| Item | Detail |
|---|---|
| Runtime | Node.js 24 (LTS) in the `node:24-bookworm-slim` image, Express 4 |
| Storage | One SQLite file (`/data/toil.db`) on a Docker volume. Login sessions are stored in the same file |
| Frontend | Single static HTML/JS page served by the app; no build step, no CDN or external assets |
| Container | Runs as non-root user `node`, listens on port 3000 inside the container, health check on `/healthz` |
| Scale | Designed for **one instance** (SQLite). Suitable for hundreds of users; not for multi-replica deployment |
| Host | Linux with Docker Engine 20.10+ and Docker Compose v2 (`docker compose`). About 150 MB RAM and ~200 MB disk for the image |
| Network (runtime) | Inbound HTTPS from users. Outbound HTTPS from the container to `login.microsoftonline.com` if Entra sign-in is enabled |
| Network (build) | Docker Hub and the npm registry, if building the image on the target host |

---

## 4. Deployment

### 4.1 Get the image

Build on the server (simplest):

```bash
unzip toil-app.zip && cd TOIL
sudo docker build -t toil-tracker:latest .
```

Or build once and use a private registry (recommended for several environments):

```bash
docker build -t registry.example.com/toil-tracker:1.0 .
docker push registry.example.com/toil-tracker:1.0
# then set TOIL_IMAGE=registry.example.com/toil-tracker:1.0 in the deployment (Portainer stack),
# or change the image: line in the compose file
```

### 4.2 Create the settings file

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` (see [Configuration reference](#5-configuration-reference)). Generate the session secret with `openssl rand -hex 32`. **Never commit `.env`**; it contains secrets.

### 4.3 Option A: Docker Compose with Caddy (HTTPS included) — recommended

Uses `docker-compose.https.yml` and `Caddyfile`. Only Caddy is published (ports 80/443); the app is not reachable directly.

In `.env` set:

```
BASE_URL=https://toil.example.com      # exactly what users type; no trailing slash
TOIL_HOST=toil.example.com             # same hostname or IP
TRUST_PROXY=1
```

Start:

```bash
sudo docker compose -f docker-compose.https.yml up -d
```

- **Public/internal DNS name with a real certificate:** delete the `tls internal` line from the `Caddyfile`. Caddy will obtain a Let's Encrypt certificate automatically (needs ports 80/443 reachable from the internet).
- **Private network:** keep `tls internal`. Caddy issues certificates from its own CA, so browsers warn until the root certificate is distributed to clients (for example by group policy):
  ```bash
  sudo docker cp toil-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
  ```
- Alternatively, mount your organisation's certificate and key in the `Caddyfile` (`tls /path/cert.pem /path/key.pem`).

### 4.4 Option B: behind your existing reverse proxy / load balancer

Run the app only, bound to localhost or an internal network, and let your proxy terminate TLS:

```bash
sudo docker run -d --name toil-tracker --restart unless-stopped \
  -p 127.0.0.1:3000:3000 -v toil-data:/data --env-file .env toil-tracker:latest
```

In `.env` set `BASE_URL=https://<public-url>` and `TRUST_PROXY=1` (the number of proxy hops in front of the app). The proxy **must** forward `Host`, `X-Forwarded-For` and `X-Forwarded-Proto`. Example nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### 4.5 Option C: Portainer

Paste `portainer-stack.yml` into **Stacks → Add stack → Web editor** and enter the variables from section 5 under *Environment variables*. The image must already exist on the host (or in a registry set via `TOIL_IMAGE`); the web editor cannot build it. Terminate TLS in front as in 4.4 (`HOST_PORT` sets the published port).

### 4.6 Plain HTTP (testing only)

`docker-compose.yml` publishes port 3000 without TLS. **Do not use this in production**: passwords and session cookies would be sent in clear text. The app prints a warning at startup when `BASE_URL` is not https.

### 4.7 Verify

```bash
sudo docker ps                        # toil-tracker: Up (healthy)
sudo docker logs toil-tracker         # should show only: TOIL Tracker running
curl -k https://<host>/healthz        # prints: ok
```

---

## 5. Configuration reference

All configuration is by environment variables (`.env` file, `--env-file`, or Portainer variables).

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | none | Public URL users browse to, e.g. `https://toil.example.com`. Must match exactly. Must be `https://` in production (controls the Secure cookie flag and HSTS) |
| `SESSION_SECRET` | Yes | none | Long random string used to sign session cookies. Changing it signs everyone out |
| `ADMIN_EMAILS` | Yes (first run) | none | Comma-separated emails. These accounts are created/promoted to **admin and reactivated on every start** |
| `AUTH_LOCAL` | No | off | Set `true` to enable email/password login |
| `ADMIN_PASSWORD` | No | none | First-run password for admins who have none (needs `AUTH_LOCAL=true`). **Remove after first start** |
| `AUTH_AZURE` | No | on if `CLIENT_ID` set | Set `false` to disable Entra sign-in |
| `TENANT_ID` | If Entra | none | Directory (tenant) ID |
| `CLIENT_ID` | If Entra | none | Application (client) ID |
| `CLIENT_SECRET` | If Entra | none | Client secret *value* (not the secret ID). Note its expiry date |
| `TRUST_PROXY` | If proxied | off | Set to `1` (hops) **only** when a reverse proxy is in front. Leave blank if the app is reachable directly, otherwise people can spoof their IP address and bypass the login lockout |
| `TOIL_HOST` | Compose/Caddy | none | Hostname or IP for the Caddy site address (used only by `docker-compose.https.yml`) |
| `PORT` | No | `3000` | Port inside the container |
| `DB_PATH` | No | `/data/toil.db` | SQLite file location (keep on the volume) |

---

## 6. Microsoft Entra ID (Azure AD) sign-in and MFA

1. **Entra admin centre → Applications → App registrations → New registration.** Name it (for example "TOIL Tracker"), supported account types: *this organizational directory only*.
2. Add a **Web** redirect URI: `<BASE_URL>/auth/callback` (for example `https://toil.example.com/auth/callback`). Entra only allows plain http for localhost.
3. **Certificates & secrets → New client secret.** Copy the **Value** immediately into `CLIENT_SECRET`. Diarise the expiry; when it expires, sign-in stops until the secret is replaced.
4. Copy **Application (client) ID** and **Directory (tenant) ID** into `CLIENT_ID` and `TENANT_ID`.
5. The app requests only the `openid`, `profile` and `email` scopes (no extra API permissions or admin consent needed).
6. **MFA:** the application does not prompt for MFA itself. Create a **Conditional Access policy** targeting this application with *Require multifactor authentication*. All Entra sign-ins then follow your tenant policy.
7. Optional: on the matching **Enterprise application**, enable *Assignment required* to restrict who can authenticate at all.
8. Users are matched by **email / user principal name** on their first sign-in. An admin must add each person in TOIL Tracker using the same address they sign in to Microsoft with. At that first sign-in the person's immutable Microsoft **object ID** is stored against their account, and from then on the account is recognised by that ID, so a re-used or renamed email/UPN cannot take over someone's TOIL account. If someone's Microsoft account is recreated, an admin uses **Unlink Microsoft** on the Users list so the new account can link.
9. Sign-in uses the authorisation-code flow with a random `state` value and PKCE (S256), and the tenant ID in the token is checked against `TENANT_ID` when that is a directory GUID.

> Local email/password accounts do **not** go through Entra, so they **bypass MFA**. Use them only where Entra is not possible (for example a break-glass admin), or disable them with `AUTH_LOCAL=false`.

---

## 7. First run and user administration

1. Set `ADMIN_EMAILS` (and `ADMIN_PASSWORD` if using local login) and start the application.
2. Sign in as the admin. Remove `ADMIN_PASSWORD` from the environment and recreate the container.
3. **Admin → Teams:** create the teams.
4. **Admin → Add user:** enter email, full name, role, and tick the team(s). For local login, set an initial password and tell the user to change it (Change password in the header).
   - *Teammate* belongs to the ticked teams; *Team lead* and *Director* manage them; *Admin* sees everything and needs no team.
   - Each person has one role, applied to all their selected teams.
5. **Edit** on the Users list changes name, role and teams. **Unlink Microsoft** (shown for people who have signed in with Entra) clears the stored Microsoft account link. **Remove** deactivates the account immediately (existing sessions stop working) but **keeps all history**. Re-adding the same email restores it.
6. **Settings → Allow negative balances** controls whether people can take more time than they have banked.

---

## 8. Operations

**Health and logs**
- `GET /healthz` returns `ok` (the container health check uses it).
- Logs go to stdout: `sudo docker logs -f toil-tracker`.

**Backup** (the whole application state is one SQLite file). Take an online, consistent backup:

```bash
sudo docker exec toil-tracker node -e "require('better-sqlite3')('/data/toil.db',{readonly:true}).backup('/data/backup.db').then(()=>console.log('backup ok'))"
sudo docker cp toil-tracker:/data/backup.db ./toil-$(date +%F).db
sudo docker exec toil-tracker rm /data/backup.db
```

Schedule this (cron) and copy the file off the host. Treat backups as **sensitive**: they contain names, emails, TOIL records and password hashes.

**Restore**

```bash
sudo docker stop toil-tracker
sudo docker run --rm -v toil-data:/data -v "$PWD":/b alpine sh -c \
  'rm -f /data/toil.db-* && cp /b/toil-YYYY-MM-DD.db /data/toil.db && chown 1000:1000 /data/toil.db'
sudo docker start toil-tracker
```

(If using the compose files, the volume is named `toil-data`; with other project names, check `docker volume ls`.)

**Upgrade**
1. Take a backup.
2. Replace the project files with the new release, then `sudo docker build -t toil-tracker:latest .`
3. Recreate the container (`docker compose -f docker-compose.https.yml up -d --force-recreate`, or remove and re-run). A rebuilt image does not replace a running container on its own.
4. Database changes are applied automatically at startup and are additive. Users are signed out once.

**Rotate secrets:** changing `SESSION_SECRET` signs everyone out; replace `CLIENT_SECRET` before it expires.

**Data retention:** the application never hard-deletes users or audit rows. If you need erasure to meet a policy, it must be done directly in the database after a backup.

---

## 9. Security

**In place**
- All database queries are parameterised. Every route enforces permissions server-side, including access to other people's entries.
- Passwords hashed with bcrypt (cost 12) in a small pool of **worker threads**, so a flood of login attempts cannot stall the application; excess load is refused with HTTP 503. Generic login errors and dummy hashing for unknown accounts avoid account enumeration.
- Strict server-side input validation: hours must be real numbers (max 2 decimals), dates must be real calendar dates in range, text fields have length limits, and malformed values are rejected with 400.
- Every administrative action is written to the admin activity log; entry changes are written to the entry audit trail in the same database transaction as the change.
- Login lockout over a 15-minute window: 5 failures per IP+email, 20 per email, 30 per IP.
- Session cookie is `HttpOnly`, `SameSite=Lax`, `Secure` over https, 8-hour lifetime, regenerated at login. Removing a user ends their access immediately.
- Response headers: HSTS (when https), `Content-Security-Policy` (same-origin only for connections, forms, frames and objects; `X-Frame-Options: DENY`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, cross-origin isolation headers, `Cache-Control: no-store` on API and auth responses, and no `X-Powered-By`.
- Entra sign-in uses `state` and PKCE and binds each person to their Microsoft object ID.
- Container runs as non-root. `.env` is excluded from the image.
- Node 24 LTS base image (Node 20 reached end-of-life in April 2026).

**Operational requirements**
- Serve over HTTPS only. Restrict access to your corporate network or VPN where possible.
- Set `TRUST_PROXY` only when a proxy is genuinely in front.
- Protect `.env`, backups and the Docker socket; anyone with Docker access on the host can read the environment and the database.
- Keep the base image updated (rebuild periodically) and review `npm audit` output.

See [Known limitations](#11-known-limitations) for security items still open in this release.

---

## 10. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Sign-in appears to work but returns to the login page | `BASE_URL` is https but `TRUST_PROXY` is not set (or the proxy is not sending `X-Forwarded-Proto`). Set `TRUST_PROXY=1` and recreate |
| "Not signed in" after login over http while `BASE_URL` is https | Browser reached the app over http. Use the https URL |
| Entra error about redirect URI | The registered URI must exactly equal `<BASE_URL>/auth/callback` |
| "Your account has not been added" after Entra login | Admin has not added that email/UPN in the Users tab |
| "Server busy. Please try again shortly." (HTTP 503) | Many password checks arrived at once and the queue was full. It clears by itself; repeated occurrences suggest a login flood, so check the source in the proxy logs |
| "linked to a different Microsoft account" | The person's Microsoft account was recreated. An admin clicks **Unlink Microsoft** on their row, then the person signs in again |
| "Sign-in session expired or invalid" | The Microsoft sign-in took longer than 10 minutes, was opened in another browser, or was replayed. Start again from the login page |
| Too many attempts message | Lockout window (15 minutes) reached; wait, or restart the container to clear it |
| Changes to the Dockerfile or code not visible | Image rebuilt but container not recreated. Remove and recreate the container |
| Port already in use | Another service holds 80/443/3000. Check `sudo ss -tlnp` and change `HOST_PORT`/ports |
| Caddy shows certificate warning | Expected with `tls internal` until the Caddy root CA is trusted on clients |
| `docker build` fails at `npm ci` with node-gyp errors | The Dockerfile must keep `--ignore-scripts` (the SQLite module ships a prebuilt binary and the slim image has no compiler) |
| Cannot write to database after a manual restore | File ownership. It must be owned by uid 1000 (`chown 1000:1000 /data/toil.db`) |

---

## 11. Known limitations

**Functional**
- Single instance only (SQLite). No high-availability or multi-replica deployment.
- No email, Teams or Outlook notifications or calendar integration yet.
- No approval workflow, public-holiday calendar, CSV/Excel export or expiry of banked hours.
- Users are provisioned manually; there is no automatic provisioning or Entra group-to-role mapping.
- One role per person across all their teams.
- Date limits (2026–2100) are constants in `server.js` and the form fields.

**Security: remaining low-severity items** (from the internal code review; the medium-severity items were fixed)
- The Content-Security-Policy still allows inline scripts, because the page uses inline event handlers. It blocks external connections, framing and form hijacking, but a full script lockdown would need the front end refactored.
- `/logout` is a GET request, so a malicious page can sign a user out (no data is exposed).
- Changing a password does not end the person's other sessions (removing a user does).
- Admins can set a local password for an Entra user, creating a sign-in path that bypasses MFA. Set `AUTH_LOCAL=false` if you do not need local accounts.
- Anyone listed in `ADMIN_EMAILS` is re-promoted and reactivated on every start. Remove people from that list when they stop being admins.
- `npm audit` reports 2 moderate findings in `uuid` (a dependency of `msal-node`). They relate to a uuid API this application does not call directly; update `msal-node` when a release resolves them.
- Passwords are hashed with bcrypt, which uses only the first 72 bytes of a password.

Restrict access to your corporate network or VPN where you can, and keep the base image and dependencies updated.

---

## 12. Production go-live checklist

- [ ] Image built (or pulled from the registry) and tagged; Node 24 base image
- [ ] `.env` created with strong `SESSION_SECRET`; file permissions `600`; not in source control
- [ ] HTTPS in place with a certificate trusted by clients; `BASE_URL` is the https URL
- [ ] `TRUST_PROXY=1` set **only** if behind a proxy; direct access to port 3000 blocked at the firewall
- [ ] Entra app registered, redirect URI correct, client secret expiry diarised, Conditional Access (MFA) policy applied
- [ ] `AUTH_LOCAL` disabled, or restricted to a small number of named accounts
- [ ] `ADMIN_PASSWORD` removed after first login; at least two admins exist
- [ ] Teams created and users added with correct roles
- [ ] Container shows `Up (healthy)`; logs show no warnings
- [ ] Backup scheduled, copied off-host, and a restore tested
- [ ] Monitoring on `https://<host>/healthz` (for example Uptime Kuma)
- [ ] Access restricted to the corporate network/VPN where possible (see section 11 for the remaining low-severity items)

---

## 13. Data model

SQLite tables (created and migrated automatically at startup):

| Table | Purpose |
|---|---|
| `users` | Email, name, role (`member` or `admin`), password hash (local login only), linked Microsoft object ID, active flag |
| `teams` | Team names |
| `team_members` | Which users are teammates of which teams |
| `team_managers` | Which users manage which teams, with title (`lead` or `director`) |
| `entries` | TOIL records: user, date, hours, type (`earned`/`taken`), reason |
| `audit` | Immutable history of entry changes: actor, owner, action, before/after JSON, note, UTC timestamp |
| `admin_log` | History of administrative actions: actor, action, details (JSON, no secrets), UTC timestamp |
| `branding` | The uploaded logo image (single row) |
| `settings` | Admin settings (for example `allow_negative`) |
| `sessions` | Login sessions (cookie-based, 8-hour expiry) |

Dates are stored as plain `YYYY-MM-DD`; audit timestamps are UTC. The browser's local date is used for "today" in reports.

---

## 14. Files in this package

| File | Purpose |
|---|---|
| `server.js`, `public/index.html` | The application (backend and single-page frontend) |
| `package.json`, `package-lock.json` | Dependencies (pinned) |
| `Dockerfile`, `.dockerignore` | Container image |
| `docker-compose.https.yml`, `Caddyfile` | Production stack: app plus HTTPS proxy |
| `docker-compose.yml` | App only, plain http (testing) |
| `portainer-stack.yml` | Stack definition for Portainer |
| `.env.example` | Template for the settings file |
