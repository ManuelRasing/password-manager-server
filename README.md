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

### 5. Run the tests

Tests run against an **isolated `test` Postgres schema** in the same Neon database —
production data in the `public` schema is never touched.

```bash
# One-time: generate .env.test (DATABASE_URL with &schema=test) and push the schema
#   (see test/helpers.ts; .env.test is gitignored)
npm run db:push:test

# Run the suite
npm test          # vitest run
npm run test:watch
```

`.env.test` holds `DATABASE_URL` (schema=test), a dummy `API_KEY`, and an
`ADMIN_KEY` used by the admin tests. Coverage: HMAC auth, per-user scoping
(cross-user access → 404), soft delete, vault config isolation, and the admin API.

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
| `DELETE` | `/credentials/:id` | Soft-delete a credential (sets `deletedAt`; recoverable) |
| `POST` | `/backup/google-drive` | Export all credentials to Google Drive |

### Admin (requires `X-Admin-Key` header)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/users` | Create a user (returns API key once) |
| `GET` | `/admin/users` | List all users (no keys) |
| `DELETE` | `/admin/users/:id` | Delete a user + cascade their data |
| `POST` | `/admin/credentials/cleanup` | Hard-delete soft-deleted credentials older than 30 days |

#### Restoring a soft-deleted credential

There is no in-app restore (by design — keeps the UI simple). To recover a
credential a user deleted by mistake, run this in the Neon SQL console:

```sql
UPDATE "Credential" SET "deletedAt" = NULL WHERE id = '<credential-id>';
```

Find the id by listing the user's trashed rows:

```sql
SELECT id, "siteName", "deletedAt" FROM "Credential"
WHERE "userId" = '<user-id>' AND "deletedAt" IS NOT NULL;
```

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

### Phase 14 — Automated Tests (critical paths)
- **Vitest** added; app factory extracted to `src/app.ts` (`buildApp({ rateLimit, logger })`) so tests can use `app.inject()` without binding a port; `index.ts` keeps the bootstrap + `listen`
- Tests run against an isolated `test` Postgres schema (same Neon DB, `&schema=test`) — never touches `public`. `.env.test` is gitignored
- `test/helpers.ts`: `getTestApp`, `createUser`, `signedHeaders` (mirrors the mobile HMAC signing), `adminHeaders`, `resetDb`
- 24 tests across auth / credentials / vault-config / admin covering: valid+invalid signatures, missing/expired headers, no account enumeration, per-user scoping (cross-user → 404), soft-delete behaviour, vault isolation, admin key checks, user-delete cascade, cleanup endpoint
- New scripts: `npm test`, `npm run test:watch`, `npm run db:push:test`

### Phase 12 — Soft Delete
- `Credential.deletedAt DateTime?` added; index changed to `@@index([userId, deletedAt])`
- `DELETE /credentials/:id` now sets `deletedAt` instead of hard-deleting (still returns 204); the row stays in the DB and is recoverable
- All reads (`GET /credentials`, `PUT`/`DELETE` ownership lookups, backup export) filter `deletedAt: null` — trashed rows are invisible everywhere
- New `POST /admin/credentials/cleanup` permanently removes rows soft-deleted >30 days ago; returns `{ deleted, cutoff }`
- Restore is manual via Neon SQL (`UPDATE "Credential" SET "deletedAt" = NULL WHERE id = '…'`) — see Admin API section

### Phase 10 — Multi-User
- **`User` model** added (`id`, `username`, `apiKey`, `createdAt`) — each user has fully independent credentials and vault config
- **`Credential` + `VaultConfig`**: added `userId String @default("migrating")` for safe migration of existing rows; `VaultConfig.userId` is `@unique` (one vault config per user). FK relations enforced at application level (auth middleware) — no DB-level FK because the staged migration would have failed
- **`auth.ts`** rewritten: requires `X-Username` header; looks up the user's `apiKey` from the DB and uses it as the HMAC secret; attaches `request.userId` for downstream handlers. Same 401 message for unknown username and bad signature (no enumeration)
- **All credential / vault-config routes**: now scoped by `userId` in every WHERE / data clause; ownership-failures return 404 (no leak)
- **`backup.ts`**: filename now includes the username (`password-manager-backup-{username}-{ts}.json`); export contains only the requesting user's credentials
- **`/admin/*` routes** (new): secured by `ADMIN_KEY` env var (separate from per-user API keys, constant-time comparison). Endpoints: `POST /admin/users`, `GET /admin/users`, `DELETE /admin/users/:id`. Generated API key returned ONCE on creation. User delete cascades credentials + vault-config inside a transaction
- **Startup bootstrap**: on first boot after schema push, if `User` table is empty and `API_KEY` is set, creates `admin` user owning the existing data; logs the migration count
- New env var: `ADMIN_KEY` (required for `/admin/*` access; if unset the admin API returns 503)

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
