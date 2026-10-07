# Cloudflare Email Gateway

[English](#english) | [中文](./README_zh.md)

---

## English

A secure, lightweight serverless email gateway running on Cloudflare Workers, powered by the **Resend API**. It allows you to send transactional and notification emails via your custom domains safely and quickly. The compose page validates Cloudflare Access JWTs inside the Worker, so the page is not rendered unless Access authentication has passed.

### ✨ Features

- **Ultra-low Latency**: Powered by Cloudflare's global edge network.
- **Secure Authentication**: The compose page and `/api/send` require a valid Cloudflare Access JWT; the legacy JSON API can still use a Client Token.
- **Environment Driven**: Fully decoupled configuration via environment variables—no hardcoded emails.
- **Mail Composer UI**: Visit the custom Worker domain to send email from a webmail-like compose page protected by Cloudflare Access.
- **Rich Format Support**: Supports multiple recipients, Cc, Bcc, Reply-To, rich text, plain text fallback, and attachments.

### ⚙️ Environment Variables Configuration

After deploying to Cloudflare Workers, configure the following variables in **Settings -> Variables**:

| Variable             | Type         | Description                                                                                                                      |
| :------------------- | :----------- | :------------------------------------------------------------------------------------------------------------------------------- |
| `RESEND_API_KEY`     | **Secret**   | Your API Key generated from the Resend dashboard.                                                                                |
| `CLIENT_TOKEN`       | **Secret**   | Optional. A secure random token used to authenticate the legacy `POST /` API. The Access-protected compose page does not use it. |
| `FROM_EMAIL`         | **Variable** | The sender identity (e.g., `Notification <i@yourdomain.com>`).                                                                   |
| `ACCESS_TEAM_DOMAIN` | **Variable** | Your Access team domain, for example `https://<team>.cloudflareaccess.com`.                                                      |
| `ACCESS_AUD`         | **Variable** | The **Application Audience (AUD) Tag** from your Zero Trust Access application.                                                  |

### 📨 Compose Page

After deployment, open the custom domain routed to this Worker:

```text
https://email.example.com/
```

This opens a webmail-like compose page for manually sending email. It supports:

- Multiple recipients with tag-style input.
- Cc, Bcc, and optional Reply-To.
- Subject and rich text body editing.
- Common formatting actions: headings, bold, italic, underline, strikethrough, lists, indentation, alignment, text color, highlight color, links, undo, redo, and clear formatting.
- Plain text fallback generated from the message body.
- Attachments, with a 10 MB total attachment limit in the UI.

Protect the custom domain with a Cloudflare Access application. The compose page sends through the same Worker at `POST /api/send`, so users only sign in with Access and do not need to enter `CLIENT_TOKEN`.

Recommended Access setup:

1. Go to **Zero Trust -> Access controls -> Applications**.
2. Create a **Self-hosted** application and add the public hostname, for example `email.luojie.dev`.
3. Allow only trusted users, groups, or email domains. Do not use Everyone or Bypass for this app.
4. Copy the **Application Audience (AUD) Tag** from the app's Additional settings into the Worker variable `ACCESS_AUD`.
5. Set `ACCESS_TEAM_DOMAIN` to your Access team domain, for example `https://<team>.cloudflareaccess.com`.
6. Keep `RESEND_API_KEY` and `FROM_EMAIL` configured on the Worker. Leave `CLIENT_TOKEN` unset if you only use the compose page.

`wrangler.toml` sets `workers_dev = false` so the default `*.workers.dev` URL cannot bypass the Access application on your custom domain.

### 🔀 Routes

| Route       | Method | Purpose                                   | Authentication                                                                                                                                                 |
| :---------- | :----- | :---------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | --------- | ----- | ------------------------------------------------- | ------------------------------------------------------ |
| `/`         | `GET`  | Opens the compose page.                   | Worker validates the Cloudflare Access JWT.                                                                                                                    |
| `/api/send` | `POST` | Used by the compose page to send email.   | Worker validates the Cloudflare Access JWT; no `CLIENT_TOKEN`.                                                                                                 |
| `/`         | `POST` | Legacy JSON API for programmatic sending. | **Requires `CLIENT_TOKEN` to be configured**; uses `Authorization: Bearer <CLIENT_TOKEN>`. Returns `404` when `CLIENT_TOKEN` is unset, disabling the endpoint. |     | `/health` | `GET` | Liveness probe, returns `{ ok: true, ts: <ms> }`. | No authentication; for Cloudflare/external monitoring. |

> ⚠️ **Security note**: Previous versions skipped authentication on `POST /` when `CLIENT_TOKEN` was unset, allowing open-relay abuse. This has been fixed — the endpoint now returns `404` when `CLIENT_TOKEN` is not configured.

## 🛡️ Security Mechanisms

- **JWT-only email**: The sender identity is read solely from the Access JWT `email` claim, never from the `Cf-Access-Authenticated-User-Email` request header (which can be forged).
- **Subject header injection protection**: CR/LF and control characters in the subject are replaced with spaces, and the total byte length is capped at 998.
- **Attachment size recomputation**: Attachment size is computed from the actual decoded base64 bytes, ignoring the client-supplied `size` field, preventing the 10 MB limit from being bypassed.
- **Constant-time `CLIENT_TOKEN` comparison**: Mitigates timing attacks.
- **Rate limiting**: A single sender is limited to 10 sends per 60 seconds; excess requests return `429`. (Isolate-scoped best-effort sliding window; for strong consistency use KV or Durable Objects.)
- **Audit logging**: The Worker emits send success/failure logs (sender, recipients, subject, Resend ID) viewable in the Cloudflare dashboard.
- **Resend non-JSON response handling**: When Resend returns a 502/HTML body, the Worker no longer crashes and instead returns a readable error.
- **Resend request timeout**: Requests to Resend have a 15s timeout to prevent slow upstream responses from holding the Worker; timeouts return `502`.
- **CORS**: All routes enable CORS (`Access-Control-Allow-Origin: *`) and handle `OPTIONS` preflight. Authentication is still enforced per route; `*` is safe because the Access JWT is delivered via an edge-injected header, not browser credentials.
- **Health check**: `GET /health` returns liveness without authentication, for Cloudflare/external monitoring.
- **Attachment filename sanitization**: Filenames have path separators and control characters stripped to prevent path traversal and invalid filenames reaching downstream.
- **Stricter email validation**: `isValidEmail` uses an RFC-style regex with length limits, no leading/trailing dots, and no consecutive dots to reject obviously bad data.
- **Link protocol allowlist**: The compose page's insert-link dialog only allows `http`/`https`/`mailto`, rejecting `javascript:`/`data:` and similar XSS-prone protocols.
- **Rate-limit bucket cleanup**: Long-running isolates evict expired counter buckets to avoid stale-key memory accumulation.
- **HTML body sanitization**: The email html body is lightly sanitized in the Worker — `<script>`/`<iframe>`/`<object>`/`<embed>`/`<form>` tags, `on*` event handlers, `javascript:`/`data:`/`vbscript:`/`file:` URLs, and HTML comments are stripped as defense in depth.
- **Security response headers**: The compose page adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- **Ctrl/Cmd+Enter to send**: The compose page supports keyboard shortcut submission.
- **Attachment drag-and-drop**: The attachment area supports dragging files in.
- **Consistent email validation**: The frontend `isValidEmail` matches the backend RFC-style strict validation.
- **CSP + nonce**: The compose page sets `Content-Security-Policy`; inline style/script are authorized via a per-request random `nonce`, and `default-src 'none'` blocks any external resource loading or injection.
- **/health upstream probe**: `GET /health?upstream=1` optionally probes Resend API reachability (`GET /domains`, no send quota consumed) and returns `upstream`/`upstreamStatus`/`upstreamOk` fields.
- **Duplicate-submit guard**: The frontend submit handler uses an `isSending` reentrancy guard to prevent double sends from rapid Ctrl+Enter or double-click.
- **Frontend fetch timeout**: The frontend send request has a 20s `AbortController` timeout with a readable message on timeout.
- **Link auto-https**: In the insert-link dialog, typing `example.com` is automatically promoted to `https://example.com` without manually entering the protocol.
- **Recipient deduplication**: Chip insertion is case-insensitively deduplicated to avoid duplicate recipients.

### 🚀 API Usage

The legacy token API is available at `POST /api/legacy` (moved from `POST /` to allow Cloudflare Access to bypass this path without exposing the compose page):

- **URL:** `https://email.example.com/api/legacy`
- **Headers:**
  - `Content-Type: application/json`
  - `Authorization: Bearer <YOUR_CLIENT_TOKEN>`

- **Body Example (JSON):**

```json
{
  "to": "target_user@gmail.com",
  "subject": "System Alert",
  "text": "The server is running smoothly.",
  "html": "<h1>System Alert</h1><p>The server is running <strong>smoothly</strong>.</p>"
}
```

> ℹ️ To use this from outside Cloudflare Access, add a **path exclusion** for `/api/legacy` in your Access application, or issue a **Service Token** and send `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers. Without bypassing Access, requests are 302-redirected to the login page.
