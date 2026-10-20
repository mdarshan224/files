# Sohan Soft Tech — Employee File Upload Portal

A self-hosted employee file collection portal with access-code-protected share links, direct browser-to-ImageKit uploads, upload progress/retry, employee-wise history, and an admin file manager.

## What is included

- Admin sign-in at `/admin`.
- Create individual upload links with a label, optional employee hint, access code, and optional expiry.
- Employees open `/upload/:token`, enter their name and code, and upload multiple files or a folder in supported desktop browsers.
- Files go directly from the browser to ImageKit; the app server does not proxy file bytes.
- Upload progress, queued uploads, and retry for failed uploads.
- Admin search/history, employee-wise totals, ImageKit file listing, link disable/enable, and deletion from ImageKit.
- Private ImageKit API key is only read from server environment variables.

## Important ImageKit limitation

This app does not impose its own fixed file-size cap. ImageKit's plan, per-file upload limits, account storage quota, rate limits, and accepted file types still apply. A failed oversized upload is shown as a failure and can be retried after resolving the provider-side issue. ImageKit's free-plan limits can vary by file category and plan; check your current ImageKit dashboard/docs before relying on large uploads. This is not unlimited storage.

Folder upload uses the browser's folder picker (`webkitdirectory`) or dropped files. Browsers may not expose nested folder structure when dragging a folder; selecting the folder with the folder picker is preferred.

## Requirements

- Node.js 20 or newer
- An ImageKit account and its Public Key + Private Key
- A host that supports a persistent writable disk for SQLite (or adapt the database layer before deploying to an ephemeral serverless platform)
- HTTPS in production

## Run locally

1. Extract the ZIP and open a terminal in this folder.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy the environment template:

   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and set `IMAGEKIT_PUBLIC_KEY` and `IMAGEKIT_PRIVATE_KEY` from ImageKit Developer options. The URL endpoint is prefilled as `https://ik.imagekit.io/mdarshantejomaya`. Random admin credentials and a session secret are pre-generated in `.env`; see `INITIAL-LOGIN.txt`. Keep both files private and never commit `.env` or paste the private key into frontend files.
5. Start:

   ```bash
   npm start
   ```

6. Visit `http://localhost:3000/admin`, sign in, create a share link, and test it in a private/incognito browser window.

## ImageKit setup

1. Open your ImageKit dashboard and go to Developer options/API keys.
2. Copy the Public Key and Private Key into the server `.env` only. The URL endpoint is configured as `https://ik.imagekit.io/mdarshantejomaya`; it is a delivery endpoint, not an API key.
3. Keep the private key confidential. For production, use a restricted key with the minimum permissions the portal needs (upload authentication signing plus file listing and delete management). If your ImageKit account's key permissions cannot separate these needs, use the least-privilege key configuration available to your account.
4. Optionally set `IMAGEKIT_BASE_FOLDER=/SohanSoftEmployeeUploads`.
5. Confirm that your account has sufficient storage and upload allowance for the file types/sizes employees will submit.

## Deploy (persistent Node host recommended)

1. Deploy this project to a Node.js host with persistent disk support, such as a VPS or a persistent-volume app service. Do not deploy unchanged to a purely ephemeral serverless host because SQLite session and portal data must persist.
2. Configure the environment variables from `.env.example` in the hosting dashboard. Never upload `.env` to a public repository.
3. Set `NODE_ENV=production`, `TRUST_PROXY=true` only if your app is behind a trusted HTTPS reverse proxy, and configure HTTPS.
4. Use a persistent volume for the `data/` directory. Back up `data/portal.sqlite` and `data/sessions.sqlite` securely. For higher availability, migrate to managed PostgreSQL and a production session store.
5. Set a strong, unique `SESSION_SECRET` and admin password. Restrict access to the admin route at the network layer if possible. Enable host-level monitoring and regular dependency updates.
6. Configure your domain, e.g. `files.sohansoft.in`, to point to the app. Set the app's port to the host-provided `PORT`.
7. Test login, link expiry/disable, wrong code, multiple uploads, folder upload, failed upload retry, search, and deletion before sharing real employee links.

## Security notes

- Admin sessions use HTTP-only, same-site cookies; cookies are marked Secure in production.
- Login and public code verification have rate limits.
- Access codes are stored as bcrypt hashes. They are never displayed again after link creation.
- ImageKit upload signatures are generated server-side and expire after 10 minutes. The private API key is never sent to the browser.
- Upload share links are bearer-style URLs. Anyone who has both the URL and access code can submit; share them carefully and disable links when no longer needed.
- Uploaded files use ImageKit URLs. This portal's URL visibility follows the ImageKit file's access settings; for sensitive/private documents, review ImageKit's private-file/signed-URL support and adjust the implementation before production use.
- This starter records an upload only after the browser reports ImageKit success. If a browser closes between the ImageKit upload and record request, the file may exist in ImageKit without an app history record; use the ImageKit Media Library tab to reconcile.

## Routes

- `/` — redirects to `/admin`
- `/admin` — admin console
- `/upload/:token` — employee upload page
- `/api/health` — health check

## Troubleshooting

- `ImageKit rejected this file`: check ImageKit file-size/type limits, quota, keys, and account status.
- `Could not fetch ImageKit files`: confirm key permissions and ImageKit API availability.
- Login cookie not retained in production: ensure HTTPS is configured and `TRUST_PROXY=true` only when behind a trusted proxy.
- SQLite native module install fails: use a supported Node LTS runtime/build environment and run `npm install` there.


## Included configuration

- `.env` contains randomly generated admin credentials and session secret, with ImageKit keys intentionally left blank. Fill in the public and private keys before starting.
- `INITIAL-LOGIN.txt` records the generated admin username/password. Keep it confidential.
- `.env` is excluded by `.gitignore`; do not share it in a public repository.
