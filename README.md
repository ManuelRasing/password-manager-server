# Password Manager — Server

Personal password manager API built with Fastify, TypeScript, Prisma, and PostgreSQL (Neon).

## Tech Stack

| Layer | Tech |
|-------|------|
| Runtime | Node.js + TypeScript |
| Framework | Fastify 5 |
| ORM | Prisma 6 |
| Database | PostgreSQL via Neon (free tier) |
| Hosting | Render (free tier) |

---

## Security Model

### HMAC Request Signing

The raw API key is **never transmitted**. Every request must include two headers:

| Header | Value |
|--------|-------|
| `X-Timestamp` | Unix epoch in **seconds** (e.g. `1716800000`) |
| `X-Signature` | `HMAC-SHA256(apiKey, METHOD\|PATH\|TIMESTAMP\|BODY_SHA256)` as hex |

The server:
1. Rejects requests with a timestamp older than ±30 seconds (replay protection)
2. Recomputes the HMAC and compares via constant-time comparison (timing attack protection)
3. Rate-limits all IPs to 20 requests/minute

### Encrypted Payloads

The server stores only **ciphertext**. Encryption and decryption happen exclusively on the mobile device using AES-256-GCM with a key derived from the master password (PBKDF2, 310 000 iterations). The server has no knowledge of plaintext passwords.

---

## Prerequisites

- Node.js 20+
- A [Neon](https://neon.tech) account (free tier)
- A [Render](https://render.com) account (free tier, for deployment)

---

## Local Setup

### 1. Install dependencies

```bash
cd server
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Fill in `.env`:

```env
DATABASE_URL="postgresql://..."   # From Neon dashboard
API_KEY="<64-char hex string>"    # Generate with the command below
```

**Generate an API key:**

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Keep this value secret. You will paste it into:
- Render environment variables (server side)
- The mobile app's secure storage setup screen (client side)

### 3. Push the database schema

```bash
npm run db:push
```

### 4. Run in development

```bash
npm run dev
```

Server starts at `http://localhost:3000`.

---

## API Reference

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — no auth required |

### Protected (requires HMAC headers)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/credentials` | List all credentials (returns encrypted blobs) |
| `POST` | `/credentials` | Create a new credential |
| `PUT` | `/credentials/:id` | Update an existing credential |
| `DELETE` | `/credentials/:id` | Delete a credential |
| `POST` | `/backup/google-drive` | Export all credentials to Google Drive |

### Request body (`POST` / `PUT`)

```json
{
  "siteName": "GitHub",
  "usernameHint": "me@email.com",
  "encryptedPayload": "<base64 AES-256-GCM ciphertext>",
  "iv": "<base64 96-bit nonce>"
}
```

`usernameHint` is optional and stored in plaintext (it's a hint, not a secret). If you don't want it visible on the server, encrypt it into `encryptedPayload`.

### Response shape

```json
{
  "id": "uuid",
  "siteName": "GitHub",
  "usernameHint": "me@email.com",
  "encryptedPayload": "...",
  "iv": "...",
  "createdAt": "2025-01-01T00:00:00.000Z",
  "updatedAt": "2025-01-01T00:00:00.000Z"
}
```

---

## Signing Requests (HMAC Reference)

```typescript
import crypto from 'crypto'

const API_KEY = '<your-api-key>'

function signRequest(method: string, path: string, body?: unknown) {
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const bodyStr = body ? JSON.stringify(body) : ''
  const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex')
  const message = [method.toUpperCase(), path, timestamp, bodyHash].join('|')
  const signature = crypto.createHmac('sha256', API_KEY).update(message).digest('hex')
  return { 'X-Timestamp': timestamp, 'X-Signature': signature }
}

// Example
const headers = signRequest('POST', '/credentials', { siteName: 'GitHub', ... })
```

---

## Google Drive Setup

Uses OAuth2 (not Service Account) — uploads count against your personal Drive quota (15 GB free).

### 1. Create a GCP project
1. Go to [console.cloud.google.com](https://console.cloud.google.com) — sign in with your personal Google account
2. Click the project dropdown → **New Project** → name it `password-manager` → **Create**

### 2. Enable the Drive API
1. **APIs & Services** → **Library** → search `Google Drive API` → **Enable**

### 3. Configure the OAuth consent screen
1. **APIs & Services** → **OAuth consent screen**
2. User Type: **External** → **Create**
3. Fill in App name (`Password Manager`), your email for support and developer contact → **Save and Continue**
4. Skip Scopes → **Save and Continue**
5. Under **Test users** → **Add Users** → add your personal Gmail → **Save and Continue**

### 4. Create OAuth2 credentials
1. **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth client ID**
2. Application type: **Web application**
3. Name: `password-manager-server`
4. Under **Authorised redirect URIs** → **Add URI** → `http://localhost`
5. **Create** — copy the **Client ID** and **Client Secret**

### 5. Add to `.env`
```env
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
```

### 6. Run the one-time auth script
```bash
npm run auth:google
```
It prints a URL — open it, authorize with your personal Google account, then copy the `code` from the redirect URL (the page won't load, that's expected) and paste it back into the terminal.

It will print your `GOOGLE_REFRESH_TOKEN` — add it to `.env`.

### 7. Create a Drive folder and get its ID
1. Open [drive.google.com](https://drive.google.com) → create a folder named `password-manager-backups`
2. Open the folder — copy the ID from the URL:
```
https://drive.google.com/drive/folders/1ABC123XYZ...
                                        ^^^^^^^^^^^^^^ GOOGLE_DRIVE_FOLDER_ID
```

### 8. Add all four vars to Render

| Key | Value |
|-----|-------|
| `GOOGLE_CLIENT_ID` | From Step 4 |
| `GOOGLE_CLIENT_SECRET` | From Step 4 |
| `GOOGLE_REFRESH_TOKEN` | From Step 6 |
| `GOOGLE_DRIVE_FOLDER_ID` | From Step 7 |

---

## Deployment (Render)

1. Push the repo to GitHub
2. Create a new **Web Service** on Render, connect the repo
3. Set:
   - **Build command:** `npm install && npm run build && npm run db:push`
   - **Start command:** `npm start`
4. Add environment variables: `DATABASE_URL`, `API_KEY`, `LOG_LEVEL=info`
5. Deploy

Render free tier spins down after 15 minutes of inactivity. The first request after idle will take ~30 seconds to cold-start — acceptable for personal use.

---

## Project Structure

```
server/
├── prisma/
│   └── schema.prisma          # Database schema
├── src/
│   ├── index.ts               # App entry point
│   ├── types.ts               # Shared TypeScript types
│   ├── lib/
│   │   ├── hmac.ts            # HMAC signing/verification helpers
│   │   └── prisma.ts          # Prisma client singleton
│   ├── plugins/
│   │   └── auth.ts            # HMAC authentication hook
│   └── routes/
│       └── credentials.ts     # CRUD endpoints
├── .env.example
├── .gitignore
├── package.json
└── tsconfig.json
```

---

## Changelog

### Phase 1 — Server Core
- Fastify 5 + TypeScript skeleton
- Prisma 6 + Neon PostgreSQL schema
- HMAC-SHA256 request signing with replay protection (30s window)
- Constant-time signature comparison (timing attack prevention)
- Rate limiting: 20 requests/minute
- CRUD endpoints: `GET /credentials`, `POST`, `PUT /:id`, `DELETE /:id`
- Public `/health` endpoint (no auth)
- Request logging with sensitive field redaction

### Phase 7 — Vault Key Model
- `VaultConfig` Prisma model added (singleton row, `id = 'vault'`)
- `GET /vault-config` — returns `{ masterSalt, encryptedVaultKey, vaultKeyIv }` or 404 if not set up
- `PUT /vault-config` — upserts the vault config; called on first setup and on master-password rotation
- Both endpoints are behind HMAC auth
- `masterSalt` is the PBKDF2 salt (not secret); `encryptedVaultKey` is `AES-256-GCM(masterKey, vaultKey)` — useless without the master password

### Phase 9 — Notes + URL Fields
- `Credential` schema: added `url String? @db.VarChar(2048)` (plaintext, nullable)
- All credential routes updated: `url` included in body schema, select projections, create/update data
- Backup export includes `url` field
- `encryptedPayload` now stores `AES-256-GCM(JSON { password, notes? })` — server stores it opaquely (no server-side change to ciphertext handling)

### Bug Fix — DELETE 400 Bad Request
- Removed `format: 'uuid'` from `idParamSchema` in `routes/credentials.ts`; Fastify 5 + ajv-formats was validating the format before the handler could return a 404, and it could also conflict depending on ajv strict-mode config. Non-existent IDs are already handled with a 404 inside the route handler.

### Phase 2 — Google Drive Backup
- `POST /backup/google-drive` endpoint
- OAuth2 authentication with stored refresh token (uploads to personal Drive quota, not Service Account)
- One-time auth script: `npm run auth:google`
- Exports all credential records to a timestamped JSON file in a configured Drive folder
- Graceful 503 if Drive env vars are not configured
- Added `googleapis` v172 dependency
