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

The client encrypts credentials with AES-256-GCM using the vault key. A key derived from the master password with PBKDF2 (310 000 iterations) wraps the vault key. Version 2 encrypts the site name, username hint, URL, password, and notes together. Legacy records still carry plaintext site names, username hints, and URLs during the transition.

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

Create a disposable local PostgreSQL database named `password_manager_test` or
`password_manager_test_<suffix>`. Schema push and test runs require an explicit
`TEST_DATABASE_URL` using `127.0.0.1` or `[::1]` without connection options.
The integration suite clears the tables in that database before each test.

```bash
export TEST_DATABASE_URL='postgresql://test_user:test_password@127.0.0.1:5432/password_manager_test'
npm run db:push:test
npm test
npm run test:watch
```

Coverage includes HMAC auth, per-user scoping, soft deletes, vault configuration
conflicts, and the admin API. The test runner supplies a synthetic admin key.

---

## Recovery backup

The local recovery command creates a portable encrypted backup of one vault,
including deleted records. It can store legacy and version 2 credentials
together and open earlier recovery archives. The artifact contains the wrapped vault key
and unlock parameters. Site names, username hints, URLs, and credential
ciphertext are protected inside the archive. Keep the file separately from the
database and retain the master password that was current when you created it.
The Google Drive export lacks the unlock information needed for this workflow.

Run the command from the server directory. Set `RECOVERY_DATABASE_URL` privately
to the intended source database and choose a new backup file on a local
filesystem. Enter the master password using a hidden prompt in Bash or Zsh.
Backup creation can read the original deployed schema before the new revision,
credential format, and policy columns are added.

```sh
printf 'Master password: '
IFS= read -rs vault_recovery_password
printf '\n'
printf '%s\n' "$vault_recovery_password" | npm run vault:recovery -- create YOUR_USERNAME PATH_TO_BACKUP
unset vault_recovery_password
```

To rehearse recovery, prepare an empty local PostgreSQL database named
`password_manager_recovery` or `password_manager_recovery_<suffix>` with the
current schema. Provision a user there with fresh API access and leave its
vault unconfigured. Set `RECOVERY_DATABASE_URL` to that database using
`127.0.0.1` or `[::1]` without connection options. Repeat the hidden prompt
and use `restore` instead of `create`, passing the destination username and
backup path. Restore verifies the artifact and unlocks its records before it
connects to the destination. It commits the configuration and records together
only if the destination vault is empty. After restore, connect the app to the
rehearsal service with its fresh API access and verify that the master password
opens the expected synthetic credentials.

Run `npm run vault:recovery:test` for the synthetic archive round-trip and
failure checks. This command uses an in-memory destination and requires no
database or environment configuration.

## Migration rehearsal

The local `vault:migrate` command upgrades every legacy credential in one vault,
including deleted entries. Run it on the owner's machine with an encrypted
recovery backup that matches the current vault. It verifies the backup and the
master password before preparing encrypted records locally, then commits all
record changes and the vault's format policy together. IDs, timestamps, and
deletion state are preserved. An interrupted transaction rolls back, and a
completed migration can be run again safely.

The default command accepts a local PostgreSQL database named
`password_manager_migration` or `password_manager_migration_<suffix>`. Prepare
that rehearsal database with synthetic data, save and verify its recovery
backup, and pause edits. Set `MIGRATION_DATABASE_URL` explicitly with
`127.0.0.1` or `[::1]` and no connection options. Supply the master password
through the same hidden prompt used for recovery, then run
`npm run vault:migrate -- YOUR_USERNAME PATH_TO_VERIFIED_BACKUP`.

For an owner-approved live cutover, use
`npm run vault:migrate -- --live YOUR_USERNAME PATH_TO_VERIFIED_BACKUP`.
Set `MIGRATION_DATABASE_URL` privately and require `sslmode=require` in that
connection URL. The only optional URL settings are `channel_binding=require`
and `pgbouncer=true`. The live path uses the public schema.

Before connecting, the live command requires `MIGRATION_CONFIRM_OWNER` to
match the username, `MIGRATION_CONFIRM_TARGET` to match
`hostname:port/database` with port 5432 when omitted, and
`MIGRATION_VERIFIED_BACKUP_SHA256` to match the exact bytes of the encrypted
backup already verified during the restore rehearsal. The owner wizard
prepares these confirmations. Supply the master password through standard
input. The connection URL and master password stay out of command arguments
and logs. Run `npm run vault:migrate:guard:test` for synthetic target and
confirmation checks.

After migration, the API accepts encrypted v2 writes for this vault and rejects
legacy writes from older clients. Verify lookup and editing in the updated
Android app. For a rollback rehearsal, use the pre-migration backup with the
existing recovery command to restore a separate empty local recovery vault.
Keep that verified recovery point until cutover checks pass.

## API Reference

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — no auth required |
| `POST` | `/device-enrollments/redeem` | Exchange an enrollment code for read-only device access |

### Protected (requires HMAC headers)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/credentials` | List all credentials (returns encrypted blobs) |
| `POST` | `/credentials` | Create a new credential |
| `PUT` | `/credentials/:id` | Update an existing credential |
| `DELETE` | `/credentials/:id` | Soft-delete a credential (sets `deletedAt`; recoverable) |
| `GET` | `/vault-config` | Fetch the wrapped vault key, salt, nonce, and current revision |
| `POST` | `/vault-config` | Create the initial vault configuration. Returns 409 if it exists. |
| `PUT` | `/vault-config` | Replace the wrapped vault key using the revision used to unlock it. Returns 409 if that revision is stale. |
| `POST` | `/backup/google-drive` | Export all credentials to Google Drive |
| `POST` | `/device-enrollments` | Issue a five-minute enrollment code for a named device |
| `GET` | `/devices` | List the owner's connected desktops and revocation state |
| `DELETE` | `/devices/:id` | Revoke one desktop's future access |

Use the updated Android client for vault setup, master-password changes, and
version 2 credentials. Migrated vaults accept encrypted version 2 writes.

### Read-only device enrollment

An authenticated owner sends `{ "deviceName": "My Mac" }` to
`POST /device-enrollments` and receives `{ code, expiresAt }`. The Mac sends
that code to `POST /device-enrollments/redeem` and receives
`{ deviceId, deviceName, deviceToken }`. Each code expires after five minutes
and can be redeemed once. The database stores hashes of codes and tokens.

The Mac stores its token in OS secure storage and sends it in
`Authorization: Bearer <deviceToken>` over HTTPS. This token grants only
`GET /credentials` and `GET /vault-config` for its owner's vault. Vault writes
and issuing enrollment codes require owner HMAC authentication. Invalid or
revoked device access returns 401, and a write with valid read-only access
returns 403. Public redemption uses the API's request rate limit.

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

Version 2 sends the credential as a single encrypted payload.

```json
{
  "formatVersion": 2,
  "encryptedPayload": "<base64 AES-256-GCM ciphertext>",
  "iv": "<base64 96-bit nonce>"
}
```

The encrypted JSON contains `siteName`, `usernameHint`, `password`, and optional `url` and `notes`. The AES-GCM associated data is the UTF-8 string `password-manager:credential:v2`.

Legacy writes may still omit `formatVersion` or send `1` and supply a plaintext `siteName` with optional `usernameHint` and `url`. Saving a legacy credential with version 2 clears its plaintext fields. An attempt to update a version 2 record with a legacy payload returns 409.

### Response shape

```json
{
  "id": "uuid",
  "formatVersion": 2,
  "encryptedPayload": "...",
  "iv": "...",
  "createdAt": "2025-01-01T00:00:00.000Z",
  "updatedAt": "2025-01-01T00:00:00.000Z"
}
```

Legacy responses retain their previous shape with `siteName`, `usernameHint`, and `url`.

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
- The current test runner requires a disposable local PostgreSQL database through `TEST_DATABASE_URL`.
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
